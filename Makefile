.PHONY: build test race vet lint rules benchmark clean

build:
	go build -trimpath -o saase .

test:
	go test ./...

race:
	go test -race ./internal/...

vet:
	go vet ./...

rules:
	go run . rules validate

benchmark:
	go test -run '^$$' -bench . ./internal/engine

clean:
	go clean
	rm -f saase coverage.out
