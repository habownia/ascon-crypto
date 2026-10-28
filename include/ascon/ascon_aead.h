/**
 * @file ascon_aead.h
 * @brief Interfejs uwierzytelnionego szyfrowania Ascon-AEAD128 (NIST SP 800-232).
 * 
 * Odpowiedzialny: Wojciech Aleksander (Etap 2)
 */

#ifndef ASCON_AEAD_H
#define ASCON_AEAD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_AEAD128_KEY_LEN   16  /**< Dlugosc klucza K w bajtach (128 bitow) */
#define ASCON_AEAD128_NONCE_LEN 16  /**< Dlugosc nonce N w bajtach (128 bitow) */
#define ASCON_AEAD128_TAG_LEN   16  /**< Dlugosc tagu T w bajtach (128 bitow) */
#define ASCON_AEAD128_RATE      16  /**< Rozmiar bloku danych w bajtach (128 bitow wg NIST SP 800-232) */

/* Wartosc poczatkowa IV (Tabela 14 w NIST SP 800-232) */
#define ASCON_AEAD128_IV 0x00001000808c0001ULL

/* Kody powrotu */
#define ASCON_SUCCESS           0   /**< Operacja zakonczona sukcesem */
#define ASCON_TAG_MISMATCH     -1   /**< Blad weryfikacji tagu uwierzytelniajacego */
#define ASCON_INVALID_ARGUMENT -2   /**< Nieprawidlowy parametr (np. wskaznik NULL) */

/**
 * @brief Szyfruje tekst jawny i generuje tag uwierzytelniajacy.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 4.1.1 "Encryption" (strony 11-15)
 * - Algorytm: Algorithm 3 "Ascon-AEAD128 Encryption" (strona 12)
 * - Schemat blokowy: Figure 5 "Ascon-AEAD128 encryption" (strona 11)
 * - Fazy algorytmu w specyfikacji:
 *   * Initialization: wzory (17)-(20), strona 12
 *   * Processing Associated Data: wzory (21)-(26), strona 13
 *   * Processing Plaintext: wzory (27)-(35), strona 14
 *   * Finalization: wzory (36)-(41), strony 14-15
 * 
 * @param[out] ciphertext     Bufor wyjsciowy na szyfrogram (rozmiar plaintext_len).
 * @param[out] tag            Bufor wyjsciowy na 16-bajtowy tag uwierzytelniajacy.
 * @param[in]  plaintext      Wskaznik na tekst jawny.
 * @param[in]  plaintext_len  Dlugosc tekstu jawnego w bajtach.
 * @param[in]  assoc_data     Wskaznik na dane skojarzone (moze byc NULL gdy assoc_data_len == 0).
 * @param[in]  assoc_data_len Dlugosc danych skojarzonych w bajtach.
 * @param[in]  nonce          16-bajtowy wektor poczatkowy (nonce).
 * @param[in]  key            16-bajtowy klucz tajny.
 * 
 * @return ASCON_SUCCESS w przypadku sukcesu lub kod bledu.
 */
int ascon_aead128_encrypt(uint8_t *ciphertext,
                          uint8_t tag[ASCON_AEAD128_TAG_LEN],
                          const uint8_t *plaintext,
                          size_t plaintext_len,
                          const uint8_t *assoc_data,
                          size_t assoc_data_len,
                          const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                          const uint8_t key[ASCON_AEAD128_KEY_LEN]);

/**
 * @brief Odszyfrowuje szyfrogram i weryfikuje tag uwierzytelniajacy.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 4.1.2 "Decryption" (strony 15-18)
 * - Algorytm: Algorithm 4 "Ascon-AEAD128 Decryption" (strona 16)
 * - Schemat blokowy: Figure 6 "Ascon-AEAD128 decryption" (strona 15)
 * - Fazy algorytmu w specyfikacji:
 *   * Initialization: wzory (42)-(44), strona 16
 *   * Processing Associated Data: wzory (45)-(46), strona 17
 *   * Processing Ciphertext: wzory (47)-(49), strona 17
 *   * Finalization i weryfikacja tagu: wzory (50)-(53), strona 18
 * 
 * W przypadku niezgodnosci tagu funkcja czysci bufor plaintext zerami i zwraca ASCON_TAG_MISMATCH.
 * 
 * @param[out] plaintext      Bufor wyjsciowy na odszyfrowany tekst jawny (rozmiar ciphertext_len).
 * @param[in]  ciphertext     Wskaznik na szyfrogram.
 * @param[in]  ciphertext_len Dlugosc szyfrogramu w bajtach.
 * @param[in]  tag            16-bajtowy tag otrzymany do weryfikacji.
 * @param[in]  assoc_data     Wskaznik na dane skojarzone (moze byc NULL gdy assoc_data_len == 0).
 * @param[in]  assoc_data_len Dlugosc danych skojarzonych w bajtach.
 * @param[in]  nonce          16-bajtowy wektor poczatkowy (nonce).
 * @param[in]  key            16-bajtowy klucz tajny.
 * 
 * @return ASCON_SUCCESS w przypadku poprawnej weryfikacji i odszyfrowania,
 *         ASCON_TAG_MISMATCH w przypadku bledu uwierzytelnienia (brak integralnosci),
 *         lub ASCON_INVALID_ARGUMENT.
 */
int ascon_aead128_decrypt(uint8_t *plaintext,
                          const uint8_t *ciphertext,
                          size_t ciphertext_len,
                          const uint8_t tag[ASCON_AEAD128_TAG_LEN],
                          const uint8_t *assoc_data,
                          size_t assoc_data_len,
                          const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                          const uint8_t key[ASCON_AEAD128_KEY_LEN]);

/**
 * @brief Staloczasowe porownanie dwoch 16-bajtowych tagow (ochrona przed atakami czasowymi).
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 4.1.2 "Decryption" (Krok 7 w Algorytmie 4 na stronie 16: warunek weryfikacji tagu T == T')
 * - Sekcja: 4.3 "AEAD Requirements" (strona 19, wymagania bezpieczenstwa i ochrona przed atakami typu side-channel / timing analysis)
 * 
 * @return 0 gdy tagi sa identyczne, wartosc niezerowa w przeciwnym razie.
 */
int ascon_verify_tag_constant_time(const uint8_t tag_a[ASCON_AEAD128_TAG_LEN],
                                  const uint8_t tag_b[ASCON_AEAD128_TAG_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_AEAD_H */

