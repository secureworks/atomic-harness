all:
	go build -o atomic-harness *.go
clean:
	rm -f atomic-harness
	rm -rf vendor

