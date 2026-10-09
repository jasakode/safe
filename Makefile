.PHONY: build-wasm build-share

GOROOT := $(shell go env GOROOT)
OUTPUT_DIR := packages/safe/bin
NAME := safe

GOOS   ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

BUILD_DIR := $(OUTPUT_DIR)/$(GOOS)/$(GOARCH)

ifeq ($(GOOS),windows)
    LIB_EXT := .dll
    LIB_NAME := $(NAME)
else ifeq ($(GOOS),darwin)
    LIB_EXT := .dylib
    LIB_NAME := lib$(NAME)
else
    LIB_EXT := .so
    LIB_NAME := lib$(NAME)
endif

LIB := $(BUILD_DIR)/$(LIB_NAME)$(LIB_EXT)
HEADER := $(BUILD_DIR)/$(LIB_NAME).h


build-share:
	@mkdir -p "$(BUILD_DIR)"
	@echo "Building $(LIB) ..."
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -buildmode=c-shared -o "$(LIB)" ./apps/share
	@echo "Library: $(LIB)"
	@echo "Header:  $(HEADER)"
	

build-wasm:
	@mkdir -p $(OUTPUT_DIR)
	@GOOS=js GOARCH=wasm go build -o $(OUTPUT_DIR)/safe.wasm ./apps/wasm/main.go
	@cp "$(GOROOT)/lib/wasm/wasm_exec.js" $(OUTPUT_DIR)/
