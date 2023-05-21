all: bin/atomic-harness bin/atrutil

bin/atomic-harness: cmd/harness/*.go
	go build -o bin/atomic-harness ./cmd/harness/

bin/atrutil: cmd/atrutil/*.go
	go build -o bin/atrutil ./cmd/atrutil/

clean:
	rm -f atomic-harness ./bin/atomic-harness ./bin/atrutil
	rm -rf vendor

