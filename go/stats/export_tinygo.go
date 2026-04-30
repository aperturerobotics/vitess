//go:build tinygo

/*
Copyright 2019 The Vitess Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package stats

import (
	"strconv"
	"strings"
	"sync"
)

type varValue interface {
	String() string
}

// NewVarHook is the type of a hook to export variables in a different way.
type NewVarHook func(name string, v varValue)

type varGroup struct {
	sync.Mutex
	vars       map[string]varValue
	newVarHook NewVarHook
}

func (vg *varGroup) register(nvh NewVarHook) {
	vg.Lock()
	defer vg.Unlock()
	if vg.newVarHook != nil {
		panic("You've already registered a function")
	}
	if nvh == nil {
		panic("nil not allowed")
	}
	vg.newVarHook = nvh
	for k, v := range vg.vars {
		nvh(k, v)
	}
	vg.vars = nil
}

func (vg *varGroup) publish(name string, v varValue) {
	vg.Lock()
	defer vg.Unlock()
	if vg.newVarHook != nil {
		vg.newVarHook(name, v)
		return
	}
	vg.vars[name] = v
}

var defaultVarGroup = varGroup{vars: make(map[string]varValue)}

// Register allows you to register a callback function
// that will be called whenever a new stats variable gets
// created.
func Register(nvh NewVarHook) {
	defaultVarGroup.register(nvh)
}

// Publish registers a variable for hooks.
func Publish(name string, v varValue) {
	publish(name, v)
}

func publish(name string, v varValue) {
	defaultVarGroup.publish(name, v)
}

// PushBackend is an interface for any stats/metrics backend that requires data
// to be pushed to it.
type PushBackend interface {
	// PushAll pushes all stats to the backend.
	PushAll() error
}

// RegisterPushBackend is a TinyGo no-op. TinyGo builds in this fork avoid the
// expvar/http-backed metrics surface entirely.
func RegisterPushBackend(_ string, _ PushBackend) {}

// FloatFunc converts a function that returns
// a float64 as a stats variable.
type FloatFunc func() float64

// Help returns the help string.
func (f FloatFunc) Help() string {
	return "help"
}

// String is the implementation of Variable.
func (f FloatFunc) String() string {
	return strconv.FormatFloat(f(), 'g', -1, 64)
}

// String is a stats string variable.
type String struct {
	mu sync.Mutex
	s  string
}

// NewString returns a new String.
func NewString(name string) *String {
	v := new(String)
	publish(name, v)
	return v
}

// Help returns the help string.
func (v *String) Help() string {
	return "help"
}

// Set sets the value.
func (v *String) Set(value string) {
	v.mu.Lock()
	v.s = value
	v.mu.Unlock()
}

// Get returns the value.
func (v *String) Get() string {
	v.mu.Lock()
	s := v.s
	v.mu.Unlock()
	return s
}

// String is the implementation of Variable.
func (v *String) String() string {
	return strconv.Quote(v.Get())
}

// StringFunc converts a function that returns
// a string as a stats variable.
type StringFunc func() string

// Help returns the help string.
func (f StringFunc) Help() string {
	return "help"
}

// String is the implementation of Variable.
func (f StringFunc) String() string {
	return strconv.Quote(f())
}

// JSONFunc is the public type for a single function that returns json directly.
type JSONFunc func() string

// Help returns the help string.
func (f JSONFunc) Help() string {
	return "help"
}

// String is the implementation of Variable.
func (f JSONFunc) String() string {
	return f()
}

// PublishJSONFunc publishes any function that returns
// a JSON string as a variable.
func PublishJSONFunc(name string, f func() string) {
	publish(name, JSONFunc(f))
}

// StringMapFunc is the function equivalent of StringMap.
type StringMapFunc func() map[string]string

// Help returns the help string.
func (f StringMapFunc) Help() string {
	return "help"
}

// String is used by stats variables.
func (f StringMapFunc) String() string {
	m := f()
	if m == nil {
		return "{}"
	}
	return stringMapToString(m)
}

func stringMapToString(m map[string]string) string {
	var b strings.Builder
	b.WriteByte('{')
	firstValue := true
	for k, v := range m {
		if firstValue {
			firstValue = false
		} else {
			b.WriteString(", ")
		}
		b.WriteByte('"')
		b.WriteString(k)
		b.WriteString(`": `)
		b.WriteString(strconv.Quote(v))
	}
	b.WriteByte('}')
	return b.String()
}
