/**
 * @file ascon_hash.h
 * @brief Interfejs funkcji skrotu Ascon-Hash256 i Ascon-XOF128 (NIST SP 800-232).
 * 
 * Odpowiedzialny: Jakub Duliban (Etap 2)
 */

#ifndef ASCON_HASH_H
#define ASCON_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_HASH256_DIGEST_LEN 32  /**< Dlugosc wyjscia Ascon-Hash256 w bajtach (256 bitow) */
#define ASCON_HASH256_RATE        8  /**< Rozmiar bloku w bajtach (64 bity) */
#define ASCON_XOF128_RATE         8  /**< Rozmiar bloku absorbujacego XOF w bajtach (64 bity) */

/* Wartosci poczatkowe IV (Tabela 14 w NIST SP 800-232) */
#define ASCON_HASH256_IV 0x0000080100cc0002ULL
#define ASCON_XOF128_IV  0x0000080000cc0003ULL
#define ASCON_CXOF128_IV 0x0000080000cc0004ULL                                    

/**
 * @brief Oblicza 256-bitowy skrot kryptograficzny wiadomosci w trybie Ascon-Hash256.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 5.1 "Specification of Ascon-Hash256" (strony 23-25)
 * - Algorytm: Algorithm 5 "Ascon-Hash256(M)" (strona 24)
 * - Schemat blokowy: Figure 7 "Structure of Ascon-Hash256 and Ascon-XOF128" (strona 23)
 * - Fazy algorytmu w specyfikacji:
 *   * Initialization: wzory (54)-(55), strona 24 (IV = 0x0000080100cc0002, permutacja p[12] lub stan precomputed z Tabeli 12 na stronie 40)
 *   * Absorbing: wzory (56)-(61), strony 24-25 (bloki 64-bitowe, funkcja pad(M, 64), permutacja p[12])
 *   * Squeezing: wzory (62)-(65), strona 25 (wyciskanie 4 blokow 64-bitowych oddzielonych p[12] do uzyskania 256-bitowego digestu)
 * - Wektor poczatkowy IV: Tabela 14 oraz Dodatek B (strony 40-41)
 * 
 * @param[out] digest   Bufor na 32-bajtowy skrot wyjsciowy.
 * @param[in]  data     Wskaznik na wiadomosc wejsciowa.
 * @param[in]  data_len Dlugosc wiadomosci w bajtach.
 * @return 0 w przypadku sukcesu, wartosc ujemna w przypadku bledu (np. NULL pointer).
 */
int ascon_hash256(uint8_t digest[ASCON_HASH256_DIGEST_LEN],
                  const uint8_t *data,
                  size_t data_len);

/**
 * @brief Oblicza funkcje o rozszerzalnym wyjsciu w trybie Ascon-XOF128.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 5.2 "Specification of Ascon-XOF128" (strony 25-27)
 * - Algorytm: Algorithm 6 "Ascon-XOF128(M, L)" (strona 26)
 * - Schemat blokowy: Figure 7 "Structure of Ascon-Hash256 and Ascon-XOF128" (strona 23)
 * - Fazy algorytmu w specyfikacji:
 *   * Initialization: wzory (66)-(67), strona 26 (IV = 0x0000080000cc0003, permutacja p[12] lub stan precomputed z Tabeli 12 na stronie 40)
 *   * Absorbing: wzory (68)-(73), strony 26-27 (bloki 64-bitowe, permutacja p[12])
 *   * Squeezing: wzory (74)-(78), strona 27 (wyciskanie strumienia wyjsciowego o zadanej dlugosci L bitow za pomoca p[12])
 * - Wektor poczatkowy IV: Tabela 14 oraz Dodatek B (strony 40-41)
 * 
 * @param[out] out      Bufor na strumien wyjsciowy o zadanej dlugosci out_len.
 * @param[in]  out_len  Zadana dlugosc strumienia wyjsciowego w bajtach.
 * @param[in]  data     Wskaznik na wiadomosc wejsciowa.
 * @param[in]  data_len Dlugosc wiadomosci w bajtach.
 * @return 0 w przypadku sukcesu, wartosc ujemna w przypadku bledu.
 */
int ascon_xof128(uint8_t *out,
                 size_t out_len,
                 const uint8_t *data,
                 size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_HASH_H */

