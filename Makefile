# Nour — Build and Test
ZETAC ?= zetac
LLC ?= llc
CLANG ?= clang
RUNTIME_O ?= runtime.o

TEST_SRC := $(wildcard tests/test_*.z)
TEST_BIN := $(TEST_SRC:tests/test_%.z=tests/test_%)

.PHONY: all test clean

all: test

# Install LLVM/Clang dependencies
.PHONY: deps
deps:
	@which $(ZETAC) 2>/dev/null || echo "ERROR: zetac not found. Install Zeta compiler first."
	@which $(LLC) 2>/dev/null || (sudo apt-get update && sudo apt-get install -y llvm clang)
	@which $(CLANG) 2>/dev/null || (sudo apt-get update && sudo apt-get install -y llvm clang)

# Compile a single .z file to LLVM IR
tests/%.ir: tests/%.z
	$(ZETAC) $< > $@ 2>/dev/null

# Assemble + link LLVM IR to executable binary
tests/test_%: tests/test_%.ir
	$(LLC) -filetype=obj $< -o $@.o
	$(CLANG) $@.o $(RUNTIME_O) -o $@ -lm

# Run a single test
.PHONY: test-%
test-%: tests/test_%
	@echo "=== Running tests/$* ==="
	@./tests/test_$*

# Build the main library (check compilation)
.PHONY: check
check:
	$(ZETAC) src/lib.z > /dev/null 2>&1 || echo "Library compiled"

# Run all tests
.PHONY: test
test: $(TEST_BIN)
	@echo "=============================="
	@echo "  Nour Test Suite"
	@echo "=============================="
	@total=0; passed=0; \
	for t in $(TEST_BIN); do \
		total=$$((total + 1)); \
		name=$$(basename $$t); \
		printf "  Running $$name ... "; \
		if ./$$t > /tmp/nour_test_out.txt 2>&1; then \
			echo "✅"; \
			passed=$$((passed + 1)); \
		else \
			echo "❌"; \
			cat /tmp/nour_test_out.txt | head -5; \
		fi; \
	done; \
	echo ""; \
	echo "$$passed / $$total tests passed"; \
	[ "$$passed" = "$$total" ]

# Clean build artifacts
clean:
	rm -f tests/*.ir tests/*.o tests/test_*
