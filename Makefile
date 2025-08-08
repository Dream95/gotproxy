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