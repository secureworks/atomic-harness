all:
	go build -o atomic-harness cmd/*.go
clean:
	rm -f atomic-harness
	rm -rf vendor

