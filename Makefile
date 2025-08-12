BINARY_NAME=gotproxy

MAIN_PACKAGE=./cmd

.PHONY: all
all: build

build:
	@echo "Building Go executable..."
	go build -o $(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Build complete. Executable: $(BINARY_NAME)"

.PHONY: clean
clean:
	@echo "Cleaning up..."
	go clean
	rm -f $(BINARY_NAME)
	@echo "Clean complete."

.PHONY: build-bpf
build-bpf: $(LIBBPF_OBJ) $(wildcard cmd/*.[ch]) | $(OUTPUT)
	TARGET=amd64 go generate ./cmd/
	TARGET=arm64 go generate ./cmd/