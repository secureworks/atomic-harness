all: bin/atomic-harness bin/atrutil bin/goartrun

bin/atomic-harness: cmd/harness/*.go
	GOOS=windows go build -o bin/atomic-harness ./cmd/harness/

bin/atrutil: cmd/atrutil/*.go
	GOOS=windows go build -o bin/atrutil ./cmd/atrutil/

bin/goartrun: cmd/goartrun/*.go
	GOOS=windows go build -o bin/goartrun ./cmd/goartrun/

clean:
	rm -f atomic-harness ./bin/atomic-harness ./bin/atrutil ./bin/goartrun
	rm -rf vendor

