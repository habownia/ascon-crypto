# Ascon Lightweight Cryptography (NIST SP 800-232)

Implementacja lekkiego algorytmu kryptograficznego **Ascon** zgodnie ze standardem **NIST SP 800-232** (*Lightweight Cryptography*), z przeznaczeniem na urządzenia klasy IoT (ESP8266 / ESP32).

---

## 1. Skład Zespołu i Podział Zadań

Szczegółowy harmonogram prac i macierz ról:  
[docs/schedule.md](docs/schedule.md)

Szczegółowe założenia architektoniczne i kryptograficzne:  
[docs/assumptions.md](docs/assumptions.md)

---

## 2. Struktura Projektu

```text
ascon-crypto/
├── docs/           # Założenia projektowe i harmonogram prac
│   ├── assumptions.md
│   └── schedule.md
├── include/        # Pliki nagłówkowe biblioteki (.h)
├── src/            # Pliki źródłowe implementacji (.c)
├── tests/          # Testy jednostkowe i wektory testowe NIST
├── Makefile        # Główny skrypt budowania projektu na PC
├── .gitignore      # Ignorowanie plików kompilacji i środowisk IDE
└── README.md       # Informacje o projekcie
```

---

## 3. Budowanie i Kompilacja (Wersja PC)

Projekt kompilowany jest za pomocą narzędzia `make` i kompilatora `gcc` (standard C99):

```bash
# Budowanie biblioteki z plików w katalogu src/
make

# Uruchomienie zestawu testów z katalogu tests/
make test

# Usunięcie plików tymczasowych i katalogu build/
make clean
```

