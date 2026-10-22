# Harmonogram Prac i Podział Zadań w Zespole

Projekt: **Samodzielna implementacja algorytmu Ascon (NIST SP 800-232) na urządzenia IoT (ESP8266/ESP32)**  
Skład zespołu: **Wojciech Aleksander**, **Jakub Duliban**, **Hubert Krzyżak**

---

## 1. Skład Zespołu i Podział Odpowiedzialności

* **Jakub Duliban**:
  - Implementacja permutacji `Ascon-p` oraz funkcji pomocniczych wykorzystywanych przez pozostałe moduły.
  - Realizacja funkcji skrótu i XOF na bazie permutacji.
* **Wojciech Aleksander**:
  - Implementacja szyfrowania i deszyfrowania w trybie `Ascon-AEAD128`.
  - Rozszerzenie o dodatkowe warianty algorytmu.
* **Hubert Krzyżak**:
  - Przygotowanie środowiska testowego i konfiguracji kompilacji na PC.
  - Weryfikacja implementacji testami pozytywnymi (wektory NIST), negatywnymi i brzegowymi.

---

## 2. Harmonogram Prac (Etapy)

### Etap 1: Inicjalizacja (Termin: 21–22 października)
- Określenie szczegółowych założeń projektu.
- Określenie harmonogramu i podziału zadań w zespole

### Etap 2: Rozszerzenie funkcji i testowanie (Termin: 18–19 listopada)
- **Jakub Duliban**: Implementacja permutacji Ascon-p oraz funkcji pomocniczych. Realizacja funkcji skrótu i XOF na bazie permutacji.
- **Wojciech Aleksander**: Implementacja szyfrowania i deszyfrowania w trybie Ascon-AEAD128. Rozszerzenie o dodatkowe warianty.
- **Hubert Krzyżak**: Konfiguracja środowiska testowego. Weryfikacja implementacji testami pozytywnymi (wektory NIST), negatywnymi i brzegowymi.

### Etap 3: Wstępny port na IoT (Prezentacja) (Termin: 16–17 grudnia)
- Przeniesienie i uruchomienie poprawnego kryptograficznie kodu na urządzeniu docelowym.
- Przeprowadzenie pierwszej analizy wydajności.
- Publiczna prezentacja częściowa: podstawy teoretyczne metody, testy oraz pierwsze wyniki z platformy IoT.

### Etap 4: Optymalizacja i Finalizacja (Termin: 27–28 stycznia)
- Przygotowanie ostatecznego demo na sprzęcie docelowym.
- Zestawienie wydajności własnej implementacji z gotowymi bibliotekami.
- Ostateczna optymalizacja kodu źródłowego.
- Opracowanie raportu końcowego oraz końcowej prezentacji.

