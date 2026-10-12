// ghostpress/tools is a standalone application holding the offline data
// generators (vulndb-gen, fingerprint-gen). It is a separate Go module with no
// dependency on the ghostpress scanner module: it reads the scanner's data
// directory from disk (via --data-dir) and writes the generated JSON back into
// it. Build/run it from this directory, e.g. `go run ./vulndb-gen -o -`.
module ghostpress/tools

go 1.22
