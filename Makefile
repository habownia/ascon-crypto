# ==============================================================================
# Makefile - Projekt Ascon (NIST SP 800-232)
# ==============================================================================

# --- Narzedzia i flagi kompilacji ---
CC ?= gcc
AR ?= ar

# CFLAGS: domyslnie optymalizacja -O2; dla DEBUG=1 symbole debugowania -g3 -O0
ifeq ($(DEBUG), 1)
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c99 -g3 -O0
else
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c99 -O2
endif

INCLUDES = -Iinclude -Itests

# --- Katalogi i pliki ---
BUILD_DIR = build
SRC_DIR = src
TEST_DIR = tests

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/src/%.o, $(SRCS))
TARGET_LIB = $(BUILD_DIR)/libascon.a

TEST_SRCS = $(wildcard $(TEST_DIR)/*.c) $(wildcard $(TEST_DIR)/unity/*.c)
TEST_OBJS = $(patsubst $(TEST_DIR)/%.c, $(BUILD_DIR)/tests/%.o, $(TEST_SRCS))
TARGET_TEST = $(BUILD_DIR)/test_runner

.PHONY: all clean test test-permutation test-perm test-hash test-aead dirs help

# --- Cele glowne ---
all: $(TARGET_LIB)

dirs:
	@mkdir -p $(BUILD_DIR)/src $(BUILD_DIR)/tests $(BUILD_DIR)/tests/unity

# Kompilacja plikow zrodlowych z src/
$(BUILD_DIR)/src/%.o: $(SRC_DIR)/%.c | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Kompilacja plikow testowych z tests/
$(BUILD_DIR)/tests/%.o: $(TEST_DIR)/%.c | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Budowanie biblioteki statycznej libascon.a
$(TARGET_LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

# Linkowanie runnera testow
$(TARGET_TEST): $(TEST_OBJS) $(TARGET_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(TEST_OBJS) -Wl,--whole-archive $(TARGET_LIB) -Wl,--no-whole-archive -o $@

# --- Uruchamianie testow TDD ---
test: $(TARGET_TEST)
	@./$(TARGET_TEST)

test-permutation: $(TARGET_TEST)
	@./$(TARGET_TEST) permutation

test-perm: test-permutation

test-hash: $(TARGET_TEST)
	@./$(TARGET_TEST) hash

test-aead: $(TARGET_TEST)
	@./$(TARGET_TEST) aead

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "Dostepne cele w Makefile:"
	@echo "  make                  - buduje biblioteke libascon.a"
	@echo "  make test             - uruchamia wszystkie testy jednostkowe"
	@echo "  make test-permutation - uruchamia testy permutacji Ascon-p"
	@echo "  make test-hash        - uruchamia testy funkcji skrotu Ascon-Hash256 / XOF128"
	@echo "  make test-aead        - uruchamia testy szyfrowania Ascon-AEAD128"
	@echo "  make clean            - usuwa katalog build/"
	@echo "  make DEBUG=1 <cel>    - kompiluje z symbolami debugowania (-g3 -O0)"
