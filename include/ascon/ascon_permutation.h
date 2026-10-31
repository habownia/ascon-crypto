/**
 * @file ascon_permutation.h
 * @brief Definicje i interfejs permutacji Ascon-p wg NIST SP 800-232.
 * 
 * Odpowiedzialny: Jakub Duliban (Etap 2)
 */

#ifndef ASCON_PERMUTATION_H
#define ASCON_PERMUTATION_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Liczba slow 64-bitowych w stanie (5 x 64 = 320 bitow). */
#define ASCON_STATE_WORDS   5
/** Rozmiar stanu w bajtach. */
#define ASCON_STATE_BYTES  40
/** Maksymalna liczba rund permutacji dopuszczona przez standard (Sekcja 3). */
#define ASCON_MAX_ROUNDS   16

/**
 * @brief 320-bitowy stan wewnetrzny Ascon (5 slow 64-bitowych S0..S4).
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 3.1 "Internal State" (strona 8)
 * - Mapowanie bajtow i bitow: Figure 9 (strona 35) oraz Figure 10 (strona 37)
 */
typedef struct {
    uint64_t x[5];
} ascon_state_t;

/**
 * @brief Stale const_0..const_15 z Tabeli 5 NIST SP 800-232.
 *
 * Runda i permutacji p[rnd] uzywa stalej c_i = const_{16 - rnd + i} (wzor 3),
 * wiec p[12] uzywa const_4..const_15 (0xf0..0x4b), a p[8] const_8..const_15
 * (0xb4..0x4b). Stale maja tylko 8 znaczacych bitow, dlatego trzymamy je jako uint8_t.
 */
extern const uint8_t ASCON_ROUND_CONSTANTS[ASCON_MAX_ROUNDS];

/**
 * @brief Inicjalizacja stanu wewnetrznego zerami.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 3.1 "Internal State" (strona 8)
 */
void ascon_state_init(ascon_state_t *s);

/**
 * @brief Bezpieczne zerowanie pamieci stanu (odporne na optymalizacje kompilatora).
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 4.3 "AEAD Requirements" (strona 19, bezpieczne usuwanie kluczy i stanow w pamieci)
 */
void ascon_state_clean(ascon_state_t *s);

/**
 * @brief Bezpieczne zerowanie dowolnego bufora (np. klucza lub bloku tymczasowego).
 *
 * Zapis przez wskaznik volatile - kompilator nie moze go usunac jako "martwego".
 */
void ascon_secure_zero(void *buf, size_t len);

/**
 * @brief Ladowanie 64-bitowego slowa z pamieci w konwencji Little-Endian.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Dodatek A.1: "Conversion Functions" (strony 35-36)
 * - Dodatek A.2: "Implementing with Integers" (strony 36-39, Table 10)
 */
uint64_t ascon_load64_le(const uint8_t *bytes);

/**
 * @brief Zapis 64-bitowego slowa do pamieci w konwencji Little-Endian.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Dodatek A.1: "Conversion Functions" (strony 35-36)
 * - Dodatek A.2: "Implementing with Integers" (strony 36-39, Table 10)
 */
void ascon_store64_le(uint8_t *bytes, uint64_t val);

/**
 * @brief Ladowanie niepelnego bloku (0..8 bajtow) jako slowa Little-Endian.
 *
 * Bajt bytes[0] trafia na najmlodsze 8 bitow wyniku, brakujace bajty sa zerami.
 * Uzywane dla ostatniego (niepelnego) bloku wiadomosci / AD / tekstu jawnego.
 *
 * @param bytes Wskaznik na dane (moze byc NULL gdy len == 0).
 * @param len   Liczba bajtow do zaladowania, 0 <= len <= 8 (wieksze wartosci sa obcinane do 8).
 */
uint64_t ascon_load_bytes_le(const uint8_t *bytes, size_t len);

/**
 * @brief Zapis najmlodszych len bajtow slowa (0..8) w konwencji Little-Endian.
 *
 * @param bytes Bufor wyjsciowy (moze byc NULL gdy len == 0).
 * @param val   Slowo zrodlowe.
 * @param len   Liczba bajtow do zapisania, 0 <= len <= 8 (wieksze wartosci sa obcinane do 8).
 */
void ascon_store_bytes_le(uint8_t *bytes, uint64_t val, size_t len);

/**
 * @brief Slowo z bitem paddingu dla bloku zawierajacego len bajtow danych (0..7).
 *
 * Padding 10* z Algorytmu 2 (pad) w reprezentacji calkowitej: bit "1" stawiany
 * jest tuz za ostatnim bajtem danych, czyli pad(len) = 0x01 << (8 * len).
 *
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja 2 "Padding rule", Algorithm 2 "pad(X, r)"
 * - Dodatek A.2, Table 11 (przyklady paddingu w postaci liczb calkowitych)
 *
 * @param len Liczba bajtow danych w bloku, 0 <= len <= 7.
 */
uint64_t ascon_pad(size_t len);

/**
 * @brief Warstwa dodawania stalej p_C: S2 = S2 xor c_i.
 *
 * Odniesienie: Sekcja 3.2, wzory (3)-(4), Table 5, Figure 1.
 */
void ascon_constant_layer(ascon_state_t *s, uint8_t round_const);

/**
 * @brief Warstwa podstawieniowa p_S: 64 rownolegle 5-bitowe S-boxy (bit-sliced).
 *
 * Kolumna j = (bit j slowa S0, ..., bit j slowa S4) przechodzi przez SBOX,
 * gdzie S0 odpowiada najstarszemu bitowi 5-bitowego wejscia x (x0).
 *
 * Odniesienie: Sekcja 3.3, wzory (5)-(7), Table 6, Figures 2-3.
 */
void ascon_substitution_layer(ascon_state_t *s);

/**
 * @brief Warstwa liniowej dyfuzji p_L: S_i = Sigma_i(S_i).
 *
 * Odniesienie: Sekcja 3.4, wzory (8)-(12), Figure 4.
 */
void ascon_linear_layer(ascon_state_t *s);

/**
 * @brief Wykonanie pojedynczej rundy permutacji Ascon-p (kroki: p_C, p_S, p_L).
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 3 "Ascon Permutations" (strony 8-10)
 * - Sekcja: 3.2 "Constant-Addition Layer p_C" (strony 8-9, Table 5, Figure 1)
 * - Sekcja: 3.3 "Substitution Layer p_S" (strony 9-10, Table 6 - SBOX, Figure 2, Figure 3)
 * - Sekcja: 3.4 "Linear Diffusion Layer p_L" (strona 10, wzory 8-12, Figure 4)
 * 
 * @param s Wskaznik na stan wewnetrzny.
 * @param round_const Stala rundy z Tabeli 5 NIST SP 800-232.
 */
void ascon_permutation_round(ascon_state_t *s, uint8_t round_const);

/**
 * @brief Wykonanie 12-rundowej permutacji Ascon-p[12] (rundy 0..11).
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 3 "Ascon Permutations" (strona 8, wzory 3-4, wykonanie 12 rund ze stalymi const_0 do const_11 z Tabeli 5)
 */
void ascon_p12(ascon_state_t *s);

/**
 * @brief Wykonanie 8-rundowej permutacji Ascon-p[8] (rundy 4..11).
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 3 "Ascon Permutations" (strona 8, wzory 3-4, wykonanie 8 rund ze stalymi const_4 do const_11 z Tabeli 5)
 */
void ascon_p8(ascon_state_t *s);

/**
 * @brief Wykonanie permutacji Ascon-p o zadanej liczbie rund (1 <= rounds <= 16).
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 3 "Ascon Permutations" (strona 8, wzor 4: p[r] sklada sie z r rund o indeksach od 12-r do 11)
 */
void ascon_p(ascon_state_t *s, unsigned int rounds);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_PERMUTATION_H */

