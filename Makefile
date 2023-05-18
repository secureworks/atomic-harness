all:
	go build -o atomic-harness ./cmd/harness/
clean:
	rm -f atomic-harness
	rm -rf vendor

