BINARY_NAME=gotproxy

MAIN_PACKAGE=./cmd

OUTPUT := .output
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT) -I./libbpf/include/uapi -I$(dir $(VMLINUX))

.PHONY: all
all: build

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) gotproxy

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

build:
	@echo "Building Go executable..."
	go build -o $(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Build complete. Executable: $(BINARY_NAME)"

.PHONY: build-bpf
build-bpf: $(LIBBPF_OBJ) $(wildcard cmd/*.[ch]) | $(OUTPUT)
	TARGET=amd64 go generate ./cmd/
	TARGET=arm64 go generate ./cmd/