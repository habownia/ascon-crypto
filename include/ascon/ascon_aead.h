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
#define ASCON_AEAD128_MIN_TAG_LEN 4 /**< Minimalna dlugosc skroconego tagu w bajtach (32 bity, wymaganie R4) */
#define ASCON_AEAD128_NM_KEY_LEN 32 /**< Dlugosc klucza K1 || K2 w wariancie z maskowaniem nonce (256 bitow) */

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
 *   * Initialization: wzory (15)-(17)
 *   * Processing Associated Data: wzory (18)-(22)
 *   * Processing Plaintext: wzory (23)-(29)
 *   * Finalization: wzory (30)-(32)
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
 *   * Initialization: wzory (33)-(35)
 *   * Processing Associated Data: wzory (36)-(40)
 *   * Processing Ciphertext: wzory (41)-(48)
 *   * Finalization i weryfikacja tagu: wzory (49)-(51)
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

/* ========================================================================== */
/* Dodatkowe warianty - Sekcja 4.2 "Implementation Options"                  */
/* ========================================================================== */

/**
 * @brief Szyfrowanie Ascon-AEAD128 ze skroconym tagiem.
 *
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 4.2.1 "Truncation" (strona 18) - tag to lambda najlewszych bitow T, T[0:lambda-1]
 * - Sekcja: 4.3 "AEAD Requirements", wymaganie R4 (strona 19) - lambda >= 32 bity,
 *   a tag krotszy niz 64 bity tylko po analizie ryzyka; dlugosc tagu musi byc stala
 *   przez caly czas zycia klucza
 *
 * Szyfrogram jest identyczny jak w ascon_aead128_encrypt(); rozni sie tylko dlugosc tagu.
 *
 * @param[out] tag     Bufor na skrocony tag o dlugosci tag_len bajtow.
 * @param[in]  tag_len Dlugosc tagu w bajtach, ASCON_AEAD128_MIN_TAG_LEN..ASCON_AEAD128_TAG_LEN.
 *
 * Pozostale parametry jak w ascon_aead128_encrypt().
 *
 * @return ASCON_SUCCESS lub ASCON_INVALID_ARGUMENT (rowniez dla tag_len spoza zakresu).
 */
int ascon_aead128_encrypt_truncated(uint8_t *ciphertext,
                                    uint8_t *tag,
                                    size_t tag_len,
                                    const uint8_t *plaintext,
                                    size_t plaintext_len,
                                    const uint8_t *assoc_data,
                                    size_t assoc_data_len,
                                    const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                                    const uint8_t key[ASCON_AEAD128_KEY_LEN]);

/**
 * @brief Deszyfrowanie Ascon-AEAD128 ze skroconym tagiem.
 *
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 4.2.1 "Truncation" (strona 18)
 * - Sekcja: 4.3 "AEAD Requirements", wymagania R4 i R5 (strona 19) - limit nieudanych
 *   deszyfrowan dla danego klucza musi pilnowac aplikacja
 *
 * Porownywane jest tylko tag_len pierwszych bajtow obliczonego tagu (w czasie stalym).
 * W przypadku niezgodnosci bufor plaintext jest zerowany.
 *
 * @return ASCON_SUCCESS, ASCON_TAG_MISMATCH lub ASCON_INVALID_ARGUMENT.
 */
int ascon_aead128_decrypt_truncated(uint8_t *plaintext,
                                    const uint8_t *ciphertext,
                                    size_t ciphertext_len,
                                    const uint8_t *tag,
                                    size_t tag_len,
                                    const uint8_t *assoc_data,
                                    size_t assoc_data_len,
                                    const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                                    const uint8_t key[ASCON_AEAD128_KEY_LEN]);

/**
 * @brief Szyfrowanie Ascon-AEAD128 z maskowaniem nonce.
 *
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 4.2.2 "Nonce Masking" (strony 18-19), wzor (52):
 *   E(K1 || K2, N, A, P) = Ascon-AEAD128.enc(K1, N xor K2, A, P)
 * - Sekcja: 4.3, wymagania R1 i R2 (strona 19) - K2 generowany jak klucz,
 *   zamaskowany nonce N xor K2 musi pozostac tajny
 *
 * Wariantu nalezy uzywac tylko gdy context-commitment i bezpieczenstwo wzgledem
 * kluczy powiazanych (related-key) nie sa wymagane.
 *
 * @param[in] key 32-bajtowy klucz K1 || K2 (K1 = bajty 0..15, K2 = bajty 16..31).
 *
 * Pozostale parametry jak w ascon_aead128_encrypt().
 *
 * @return ASCON_SUCCESS lub ASCON_INVALID_ARGUMENT.
 */
int ascon_aead128_nm_encrypt(uint8_t *ciphertext,
                             uint8_t tag[ASCON_AEAD128_TAG_LEN],
                             const uint8_t *plaintext,
                             size_t plaintext_len,
                             const uint8_t *assoc_data,
                             size_t assoc_data_len,
                             const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                             const uint8_t key[ASCON_AEAD128_NM_KEY_LEN]);

/**
 * @brief Deszyfrowanie Ascon-AEAD128 z maskowaniem nonce.
 *
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja: 4.2.2 "Nonce Masking" (strony 18-19), wzor (53):
 *   D(K1 || K2, N, A, C, T) = Ascon-AEAD128.dec(K1, N xor K2, A, C, T)
 *
 * @param[in] key 32-bajtowy klucz K1 || K2.
 *
 * @return ASCON_SUCCESS, ASCON_TAG_MISMATCH lub ASCON_INVALID_ARGUMENT.
 */
int ascon_aead128_nm_decrypt(uint8_t *plaintext,
                             const uint8_t *ciphertext,
                             size_t ciphertext_len,
                             const uint8_t tag[ASCON_AEAD128_TAG_LEN],
                             const uint8_t *assoc_data,
                             size_t assoc_data_len,
                             const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                             const uint8_t key[ASCON_AEAD128_NM_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_AEAD_H */

