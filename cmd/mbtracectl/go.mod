module github.com/otfabric/go-modbus-trace/cmd/mbtracectl

go 1.23

require (
	github.com/otfabric/go-modbus-capture v0.0.2
	github.com/otfabric/go-modbus-trace v0.1.1
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

// The CLI is built from the library in this repository. v0.1.1 still contains
// this package, so the requirement alone is an ambiguous import.
replace github.com/otfabric/go-modbus-trace => ../..
