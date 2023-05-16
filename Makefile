all:
	go build -o atomic-harness cmd/harness/*.go
clean:
	rm -f atomic-harness
	rm -rf vendor

