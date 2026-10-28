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

