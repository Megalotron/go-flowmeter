# go-flowmeter
Ethernet traffic flow generator and analyser for anomaly detection written in Go.

## Run the tests
```bash
go test ./... -v -race
```

## Run the benchmark
In the desired package, run :
```bash
go test -bench=. -benchmem
```