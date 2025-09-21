# HPMon Makefile
# eBPF-based system monitoring tool

# Project configuration
PROJECT_NAME := hpmon
VERSION := 0.1.0

# Directories
SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
USER_DIR := $(SRC_DIR)/user
COMMON_DIR := $(SRC_DIR)/common
INCLUDE_DIR := include
BUILD_DIR := build
BUILD_DIR_TEST := $(BUILD_DIR)/tests
TEST_DIR := tests

# Generated files
VMLINUX_H := $(BUILD_DIR)/vmlinux.h

# Compiler configuration
CC := gcc
CLANG := clang
LLVM_STRIP := llvm-strip
BPFTOOL := bpftool

# Compiler flags
CFLAGS := -Wall -Wextra -pedantic -O2 -g
CFLAGS += -I$(INCLUDE_DIR) -I$(COMMON_DIR)
CFLAGS += $(shell pkg-config --cflags libbpf)

LDFLAGS := $(shell pkg-config --libs libbpf)
LDFLAGS += -lelf -lz -lm -lpthread -lncurses

# eBPF specific flags
BPF_CFLAGS := -O2 -target bpf -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS += -I$(INCLUDE_DIR) -I$(COMMON_DIR)
BPF_CFLAGS += -I$(BUILD_DIR)
BPF_CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS += -I/usr/include/bpf
BPF_CFLAGS += -D__BPF_TRACING__
BPF_CFLAGS += -g -Wall -Werror

# Source files
USER_SOURCES := $(wildcard $(USER_DIR)/*.c)
COMMON_SOURCES := $(wildcard $(COMMON_DIR)/*.c)
BPF_SOURCES := $(wildcard $(BPF_DIR)/*.bpf.c)

# Object files
USER_OBJECTS := $(USER_SOURCES:$(USER_DIR)/%.c=$(BUILD_DIR)/user/%.o)
COMMON_OBJECTS := $(COMMON_SOURCES:$(COMMON_DIR)/%.c=$(BUILD_DIR)/common/%.o)
BPF_OBJECTS := $(BPF_SOURCES:$(BPF_DIR)/%.bpf.c=$(BUILD_DIR)/bpf/%.bpf.o)

# Target binary
TARGET := $(PROJECT_NAME)

# Test configuration
CORE_TEST_SOURCES := $(TEST_DIR)/test_core.c
CORE_TEST_OBJECTS := $(CORE_TEST_SOURCES:$(TEST_DIR)/%.c=$(BUILD_DIR_TEST)/%.o)
TEST_TARGET := $(BUILD_DIR_TEST)/test-$(PROJECT_NAME)

# Container test configuration
CONTAINER_TEST_TARGET := $(BUILD_DIR_TEST)/test-container-bin

# CLI test configuration
CLI_TEST_TARGET := $(BUILD_DIR_TEST)/test-cli-bin

# Additional CLI test configuration
CLI_SIMPLE_TEST_TARGET := $(BUILD_DIR_TEST)/test-cli-simple-bin
CLI_BUG_FIXES_TEST_TARGET := $(BUILD_DIR_TEST)/test-cli-bug-fixes-bin
CLI_ADDITIONAL_FIXES_TEST_TARGET := $(BUILD_DIR_TEST)/test-cli-additional-fixes-bin

# Export test configuration
EXPORT_TEST_TARGET := $(BUILD_DIR_TEST)/test-export-bin

# Real-time processing test configuration
REALTIME_TEST_TARGET := $(BUILD_DIR_TEST)/test-realtime-bin

# Load test configuration
LOAD_TEST_TARGET := $(BUILD_DIR_TEST)/test-load-bin

# Load test server configuration
LOAD_SERVER_TEST_TARGET := $(BUILD_DIR_TEST)/test-load-server-bin

# Default target
.PHONY: all
all: $(TARGET)

# Create build directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/{user,common,bpf,test}

# Generate vmlinux.h
$(VMLINUX_H): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile eBPF programs
$(BUILD_DIR)/bpf/%.bpf.o: $(BPF_DIR)/%.bpf.c $(VMLINUX_H) | $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/bpf
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile user-space objects
$(BUILD_DIR)/user/%.o: $(USER_DIR)/%.c | $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/user
	$(CC) $(CFLAGS) -c $< -o $@

# Compile common objects
$(BUILD_DIR)/common/%.o: $(COMMON_DIR)/%.c | $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/common
	$(CC) $(CFLAGS) -c $< -o $@

# Compile test objects
$(BUILD_DIR_TEST)/%.o: $(TEST_DIR)/%.c | $(BUILD_DIR)
	mkdir -p $(BUILD_DIR_TEST)
	$(CC) $(CFLAGS) -c $< -o $@

# Link main binary
$(TARGET): $(USER_OBJECTS) $(COMMON_OBJECTS) $(BPF_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(USER_OBJECTS) $(COMMON_OBJECTS) $(LDFLAGS)

# Test target
$(TEST_TARGET): $(CORE_TEST_OBJECTS) $(COMMON_OBJECTS) $(filter-out $(BUILD_DIR)/user/main.o,$(USER_OBJECTS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Container test target
$(CONTAINER_TEST_TARGET): $(BUILD_DIR_TEST)/test_container.o $(COMMON_OBJECTS) $(filter-out $(BUILD_DIR)/user/main.o,$(USER_OBJECTS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# CLI test target
$(CLI_TEST_TARGET): $(BUILD_DIR_TEST)/test_cli.o $(COMMON_OBJECTS) $(filter-out $(BUILD_DIR)/user/main.o,$(USER_OBJECTS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# CLI simple test target
$(CLI_SIMPLE_TEST_TARGET): $(BUILD_DIR_TEST)/test_cli_simple.o $(COMMON_OBJECTS) $(filter-out $(BUILD_DIR)/user/main.o $(BUILD_DIR)/user/hpmon_core.o,$(USER_OBJECTS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# CLI bug fixes test target
$(CLI_BUG_FIXES_TEST_TARGET): $(BUILD_DIR_TEST)/test_cli_bug_fixes.o $(COMMON_OBJECTS) $(filter-out $(BUILD_DIR)/user/main.o $(BUILD_DIR)/user/hpmon_core.o,$(USER_OBJECTS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# CLI additional fixes test target
$(CLI_ADDITIONAL_FIXES_TEST_TARGET): $(BUILD_DIR_TEST)/test_additional_cli_fixes.o $(COMMON_OBJECTS) $(filter-out $(BUILD_DIR)/user/main.o $(BUILD_DIR)/user/hpmon_core.o,$(USER_OBJECTS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Real-time processing test target
$(REALTIME_TEST_TARGET): $(BUILD_DIR_TEST)/test_realtime.o $(COMMON_OBJECTS) $(filter-out $(BUILD_DIR)/user/main.o,$(USER_OBJECTS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Export test target
$(EXPORT_TEST_TARGET): $(BUILD_DIR_TEST)/test_export.o $(COMMON_OBJECTS) $(filter-out $(BUILD_DIR)/user/main.o,$(USER_OBJECTS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Load test target
$(LOAD_TEST_TARGET): $(BUILD_DIR_TEST)/test_load.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Load test server target
$(LOAD_SERVER_TEST_TARGET): $(BUILD_DIR_TEST)/test_load_server.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Phony targets
.PHONY: test-core
test-core: $(TEST_TARGET)
	./$(TEST_TARGET)

.PHONY: test-container
test-container: $(CONTAINER_TEST_TARGET)
	./$(CONTAINER_TEST_TARGET)

.PHONY: test-cli
test-cli: $(CLI_TEST_TARGET)
	./$(CLI_TEST_TARGET)

.PHONY: test-cli-simple
test-cli-simple: $(CLI_SIMPLE_TEST_TARGET)
	./$(CLI_SIMPLE_TEST_TARGET)

.PHONY: test-cli-bug-fixes
test-cli-bug-fixes: $(CLI_BUG_FIXES_TEST_TARGET)
	./$(CLI_BUG_FIXES_TEST_TARGET)

.PHONY: test-cli-additional-fixes
test-cli-additional-fixes: $(CLI_ADDITIONAL_FIXES_TEST_TARGET)
	./$(CLI_ADDITIONAL_FIXES_TEST_TARGET)

.PHONY: test-export
test-export: $(EXPORT_TEST_TARGET)
	./$(EXPORT_TEST_TARGET)

.PHONY: test-realtime
test-realtime: $(REALTIME_TEST_TARGET)
	./$(REALTIME_TEST_TARGET)

.PHONY: test-load
test-load: $(LOAD_TEST_TARGET)
	./$(LOAD_TEST_TARGET)

.PHONY: test-load-server
test-load-server: $(LOAD_SERVER_TEST_TARGET)
	./$(LOAD_SERVER_TEST_TARGET)

.PHONY: vmlinux
vmlinux: $(VMLINUX_H)

.PHONY: test
test: test-core test-container test-cli test-cli-simple test-cli-bug-fixes test-cli-additional-fixes test-export test-realtime

.PHONY: check
check: all format lint test

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(VMLINUX_H)

.PHONY: clean-all
clean-all: clean
	docker-compose -f docker-compose.dev.yml down --rmi all --volumes

.PHONY: install
install: $(TARGET)
	install -d /usr/local/bin
	install -m 755 $(TARGET) /usr/local/bin/

.PHONY: uninstall
uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: debug
debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

.PHONY: release
release: CFLAGS += -DNDEBUG -O3
release: clean $(TARGET)

.PHONY: format
format:
	find $(SRC_DIR) $(INCLUDE_DIR) $(TEST_DIR) -name "*.c" -o -name "*.h" | xargs clang-format -i

.PHONY: lint
lint:
	@echo "Running linting on source files..."
	@for file in $$(find $(SRC_DIR) $(INCLUDE_DIR) -name "*.c" -o -name "*.h" | grep -v "\.bpf\.c"); do \
		echo "Linting $$file"; \
		if [ "$$file" = "src/user/hpmon_core.c" ] || [ "$$file" = "src/user/data_collector.c" ] || [ "$$file" = "src/user/tui.c" ]; then \
			clang-tidy --config-file=.clang-tidy-data-collector "$$file" \
				-- -I$(INCLUDE_DIR) -I$(COMMON_DIR) -I/usr/include/$(shell uname -m)-linux-gnu \
				$(shell pkg-config --cflags libbpf) -D__TARGET_ARCH_x86 || exit 1; \
		else \
			clang-tidy "$$file" \
				-- -I$(INCLUDE_DIR) -I$(COMMON_DIR) -I/usr/include/$(shell uname -m)-linux-gnu \
				$(shell pkg-config --cflags libbpf) -D__TARGET_ARCH_x86 || exit 1; \
		fi; \
	done

.PHONY: deps
deps:
	@echo "Required dependencies:"
	@echo "  - libbpf-dev"
	@echo "  - clang"
	@echo "  - clang-format"
	@echo "  - clang-tidy"
	@echo "  - llvm"
	@echo "  - libelf-dev"
	@echo "  - zlib1g-dev"
	@echo "  - linux-headers"
	@echo "  - bpftool (for vmlinux.h generation)"

.PHONY: check-deps
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists libbpf || (echo "ERROR: libbpf not found" && exit 1)
	@which clang > /dev/null || (echo "ERROR: clang not found" && exit 1)
	@which clang-format > /dev/null || (echo "ERROR: clang-format not found" && exit 1)
	@which clang-tidy > /dev/null || (echo "ERROR: clang-tidy not found" && exit 1)
	@which llvm-strip > /dev/null || (echo "ERROR: llvm-strip not found" && exit 1)
	@which bpftool > /dev/null || (echo "ERROR: bpftool not found" && exit 1)
	@echo "All dependencies found!"

.PHONY: help
help:
	@echo "HPMon Build System"
	@echo "=================="
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build the main binary (default)"
	@echo "  vmlinux     - Generate vmlinux.h for BPF programs"
	@echo "  test        - Build and run all tests (requires sudo for BPF tests)"
	@echo "  check       - Run format, lint, and all tests"
	@echo "  clean       - Remove build artifacts"
	@echo "  clean-all   - Remove build artifacts and Docker images"
	@echo "  install     - Install binary to /usr/local/bin (requires sudo)"
	@echo "  uninstall   - Remove installed binary (requires sudo)"
	@echo "  debug       - Build with debug symbols"
	@echo "  release     - Build optimized release version"
	@echo "  format      - Format source code with clang-format"
	@echo "  lint        - Run static analysis with clang-tidy"
	@echo "  deps        - Show required dependencies"
	@echo "  check-deps  - Check if dependencies are installed"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Note: BPF tests and install/uninstall require root privileges."
	@echo "      Use 'sudo make test' or 'sudo make install' as needed."

# Include dependency files if they exist
-include $(BUILD_DIR)/*/*.d
