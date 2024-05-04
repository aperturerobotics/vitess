module github.com/dolthub/vitess

go 1.26.2

require github.com/aperturerobotics/common v0.15.5 // latest

require (
	github.com/aperturerobotics/protobuf-go-lite v0.6.1
	github.com/google/go-cmp v0.6.0
	github.com/stretchr/testify v1.9.0
	golang.org/x/tools v0.45.0
	google.golang.org/grpc v1.56.3
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/aperturerobotics/json-iterator-lite v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool golang.org/x/tools/cmd/goyacc
