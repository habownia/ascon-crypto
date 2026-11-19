# Ascon Lightweight Cryptography (NIST SP 800-232)

Implementacja lekkiego algorytmu kryptograficznego **Ascon** zgodnie ze standardem **NIST SP 800-232** (*Lightweight Cryptography*), z przeznaczeniem na urządzenia klasy IoT (ESP8266 / ESP32).

Projekt obejmuje pełną implementację uwierzytelnionego szyfrowania **Ascon-AEAD128**, funkcji skrótu **Ascon-Hash256**, funkcji o rozszerzalnym wyjściu **Ascon-XOF128** oraz rdzenia permutacji **Ascon-p**.

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
│   ├── schedule.md
│   └── test_reference/     # Oficjalne wektory testowe NIST KAT (AEAD i Hash)
├── examples/       # Programy demonstracyjne i przykłady użycia
│   └── demo.c              # Interaktywne demo AEAD128 + Hash256 + symulacja ataków
├── include/        # Publiczne pliki nagłówkowe z interfejsami biblioteki (.h)
│   └── ascon/
│       ├── ascon.h
│       ├── ascon_permutation.h
│       ├── ascon_hash.h
│       └── ascon_aead.h
├── src/            # Implementacje modułów kryptograficznych (.c)
│   ├── ascon_permutation.c # Rdzeń permutacji Ascon-p, S-box, warstwa liniowa, stałe
│   ├── ascon_hash.c        # Funkcje skrótu Ascon-Hash256 i Ascon-XOF128 (konstrukcja gąbki)
│   └── ascon_aead.c        # Uwierzytelnione szyfrowanie Ascon-AEAD128
├── tests/          # Pakiet testów jednostkowych TDD i wbudowany framework Unity
│   ├── unity/              # Lekki framework testów jednostkowych Unity (C)
│   ├── test_permutation.c  # Testy permutacji, S-boxa, stałych, paddingu i Little-Endian
│   ├── test_hash.c         # Testy Ascon-Hash256 i Ascon-XOF128
│   ├── test_aead.c         # Testy szyfrowania/deszyfrowania AEAD128 i testy integralności
│   └── test_runner.c       # Główny runner testów z selekcją modułów
├── Makefile        # Skrypt automatyzacji kompilacji, budowania biblioteki, testów i demo
├── .gitignore      # Reguły ignorowania plików binarnych i tymczasowych
└── README.md       # Główna dokumentacja projektu
```

---

## 3. Szybki Start: Uruchomienie Demo

W projekcie przygotowano interaktywne demo prezentujące szyfrowanie AEAD128, weryfikację tagu, odporność na manipulacje danymi oraz funkcję skrótu Hash256 z efektem lawinowym:

```bash
# Uruchomienie demo z domyślną wiadomością
make demo

# Uruchomienie demo z własnym tekstem
make demo MSG="<wiadomosc>"

# Lub bezpośrednio przez plik binarny:
./build/demo "<wiadomosc>"
```


---

## 4. Budowanie i Uruchamianie Testów

Projekt kompilowany jest za pomocą narzędzia `make` i kompilatora `gcc` (standard C99):

```bash
# Budowanie biblioteki i uruchomienie wszystkich testów TDD (26 testów)
make test

# Uruchomienie wyłącznie testów permutacji Ascon-p
make test-permutation   # alias: make test-perm

# Uruchomienie wyłącznie testów funkcji skrótu Ascon-Hash256 / XOF128
make test-hash

# Uruchomienie wyłącznie testów uwierzytelnionego szyfrowania Ascon-AEAD128
make test-aead

# Zbudowanie samej biblioteki statycznej build/libascon.a
make

# Czyszczenie katalogu build/
make clean
```