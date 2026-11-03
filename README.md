# Ascon Lightweight Cryptography (NIST SP 800-232)

Implementacja lekkiego algorytmu kryptograficznego **Ascon** zgodnie ze standardem **NIST SP 800-232** (*Lightweight Cryptography*), z przeznaczeniem na urządzenia klasy IoT (ESP8266 / ESP32).


---

## 1. Skład Zespołu i Podział Zadań

Skład zespołu: **Wojciech Aleksander**, **Jakub Duliban**, **Hubert Krzyżak**

[Harmonogram: docs/schedule.md](docs/schedule.md)

[Założenia: docs/assumptions.md](docs/assumptions.md)

---

## 2. Struktura Projektu

```text
ascon-crypto/
├── docs/           # Założenia projektowe, harmonogram i specyfikacja NIST SP 800-232
│   ├── NIST.SP.800-232.pdf
│   ├── assumptions.md
│   └── schedule.md
├── include/        # Pliki nagłówkowe z deklaracjami interfejsów (.h)
│   └── ascon/
│       ├── ascon.h
│       ├── ascon_permutation.h
│       ├── ascon_hash.h
│       └── ascon_aead.h
├── src/            # Implementacje modułów kryptograficznych (.c)
│   ├── ascon_permutation.c
│   ├── hash.c
│   └── aead.c
├── tests/          # Pakiet testów TDD i wbudowany framework Unity
│   ├── unity/
│   ├── vectors/
│   ├── test_permutation.c
│   ├── test_hash.c
│   ├── test_aead.c
│   └── test_runner.c
├── Makefile        # Główny skrypt budowania projektu i uruchamiania testów
├── .gitignore      # Ignorowanie plików kompilacji i środowisk IDE
└── README.md       # Informacje o projekcie
```

---

## 4. Budowanie i Uruchamianie Testów

Kompilacja i uruchomienie zestawu testów na komputerze PC (Linux/GCC, standard C99):

```bash
# Budowanie biblioteki i uruchomienie wszystkich testów
make test

# Uruchomienie wyłącznie testów permutacji Ascon-p
make test-permutation   # alias: make test-perm

# Uruchomienie wyłącznie testów funkcji skrótu Ascon-Hash256 / XOF128
make test-hash

# Uruchomienie wyłącznie testów uwierzytelnionego szyfrowania Ascon-AEAD128
make test-aead

# Budowanie samej biblioteki statycznej build/libascon.a
make

# Czyszczenie katalogu build/
make clean
```
