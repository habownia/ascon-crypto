# --- Narzędzia i flagi kompilacji ---
# Operator '?=' ustawia wartość domyślną, jeśli zmienna nie została zdefiniowana
# wcześniej w środowisku (np. pozwala wywołać 'make CC=clang')
CC ?= gcc
AR ?= ar

# CFLAGS:
#   -Wall -Wextra -Wpedantic : włączenie rygorystycznych ostrzeżeń kompilatora
#   -std=c99                 : wymuszenie standardu ANSI C99
#   -O2                      : optymalizacja kodu poziomu drugiego
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c99 -O2

# Ścieżka do katalogu z plikami nagłówkowymi (.h)
INCLUDES = -Iinclude

# --- Definicje katalogów ---
BUILD_DIR = build
SRC_DIR = src
TEST_DIR = tests

# --- Automatyczne wykrywanie plików źródłowych biblioteki ---
# wildcard: wyszukuje wszystkie pliki .c w katalogu src/
SRCS = $(wildcard $(SRC_DIR)/*.c)
# patsubst: zamienia ścieżkę 'src/plik.c' na plik obiektowy 'build/plik.o'
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))
# Nazwa docelowej biblioteki statycznej
TARGET_LIB = $(BUILD_DIR)/libascon.a

# --- Automatyczne wykrywanie plików testowych ---
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS = $(patsubst $(TEST_DIR)/%.c, $(BUILD_DIR)/tests/%.o, $(TEST_SRCS))
TARGET_TEST = $(BUILD_DIR)/test_runner

# .PHONY: Deklaracja celów pozornych (niebędących fizycznymi plikami na dysku)
.PHONY: all clean test dirs help

# Domyślny cel wywoływany przy wpisaniu samego polecenia 'make'
all: dirs $(TARGET_LIB)

# Cel tworzący katalogi na pliki wynikowe
dirs:
	@mkdir -p $(BUILD_DIR) $(BUILD_DIR)/tests

# Reguła wzorca kompilacji plików źródłowych z src/ do plików obiektowych w build/
# '$<' oznacza plik źródłowy (.c), '$@' plik docelowy (.o)
# '| dirs' to order-only prerequisite – katalog musi powstać przed kompilacją
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Reguła wzorca kompilacji plików testowych z tests/ do build/tests/
$(BUILD_DIR)/tests/%.o: $(TEST_DIR)/%.c | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -Itests -c $< -o $@

# Reguła budowania biblioteki statycznej .a za pomocą archiwizatora (ar)
# Opcje 'rcs': r (zastąp/dodaj pliki), c (utwórz archiwum), s (zindeksuj symbole)
$(TARGET_LIB): $(OBJS)
	@if [ -n "$(OBJS)" ]; then \
		$(AR) rcs $@ $(OBJS); \
		echo "[OK] Biblioteka $@ została pomyślnie zbudowana."; \
	else \
		echo "[INFO] Brak plików źródłowych w katalogu $(SRC_DIR)/ (Etap 1: Inicjalizacja)."; \
	fi

# Cel 'make test': kompiluje i uruchamia testy jednostkowe
test: all
	@if [ -n "$(TEST_SRCS)" ]; then \
		$(CC) $(CFLAGS) $(INCLUDES) -Itests $(TEST_SRCS) $(TARGET_LIB) -o $(TARGET_TEST); \
		echo "[RUN] Uruchamianie testów..."; \
		./$(TARGET_TEST); \
	else \
		echo "[INFO] Środowisko testowe gotowe. Testy jednostkowe zostaną dodane w Etapie 2."; \
	fi

# Cel 'make clean': usuwa katalog build/ z plikami tymczasowymi i biblioteką
clean:
	rm -rf $(BUILD_DIR)
	@echo "[OK] Katalog $(BUILD_DIR)/ wyczyszczony."

# Cel 'make help': wyświetla krótką pomoc z dostępnymi poleceniami
help:
	@echo "Dostępne cele w Makefile:"
	@echo "  make        - buduje bibliotekę libascon.a z plików w src/"
	@echo "  make test   - kompiluje i uruchamia testy z katalogu tests/"
	@echo "  make clean  - usuwa katalog build/"
