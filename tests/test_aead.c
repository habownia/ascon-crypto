/**
 * @file test_aead.c
 * @brief Pakiet testow jednostkowych uwierzytelnionego szyfrowania Ascon-AEAD128.
 * Wektory referencyjne pochodza bezposrednio z docs/test_reference/LWC_AEAD_KAT_128_128.txt.
 */

#include "unity/unity.h"
#include "ascon/ascon_aead.h"
#include <string.h>

/**
 * @brief Wypelnia bufor sekwencyjnymi bajtami wg generatora NIST KAT.
 */
static void generate_kat_pattern(uint8_t *buf, size_t len, uint8_t start_val) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(start_val + i);
    }
}

/**
 * @brief Weryfikacja dla pustego tekstu jawnego i pustych danych skojarzonych (0 bajtow).
 */
static void test_aead128_empty_pt_empty_ad_nist_kat(void) {
    uint8_t key[ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[ASCON_AEAD128_NONCE_LEN];
    uint8_t tag[ASCON_AEAD128_TAG_LEN];

    generate_kat_pattern(key, sizeof(key), 0x00);
    generate_kat_pattern(nonce, sizeof(nonce), 0x10);

    static const uint8_t EXPECTED_TAG[ASCON_AEAD128_TAG_LEN] = {
        0x4f, 0x9c, 0x27, 0x82, 0x11, 0xbe, 0xc9, 0x31,
        0x6b, 0xf6, 0x8f, 0x46, 0xee, 0x8b, 0x2e, 0xc6
    };

    /* 1. Szyfrowanie pustego tekstu */
    int enc_res = ascon_aead128_encrypt(NULL, tag, NULL, 0, NULL, 0, nonce, key);
    TEST_ASSERT_EQUAL(ASCON_SUCCESS, enc_res);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_TAG, tag, ASCON_AEAD128_TAG_LEN);

    /* 2. Weryfikacja deszyfrowania pustego tekstu z wyliczonym tagiem */
    uint8_t decrypted[1] = {0xFF}; // dajemy długość bufora 1, bo nie można mieć pustych tablic w C
    int dec_res = ascon_aead128_decrypt(decrypted, NULL, 0, tag, NULL, 0, nonce, key);
    TEST_ASSERT_EQUAL(ASCON_SUCCESS, dec_res);
    TEST_ASSERT_EQUAL_HEX8(0xFF, decrypted[0]); //Upewniamy sie, ze bufor nie zostal nadpisany
}

/**
 * @brief Weryfikacja dla tekstu jawnego (16 bajtow)- pelny i danych skojarzonych (8 bajtow) - niepełny blok
 */
static void test_aead128_kat_with_ad_and_pt(void) {
    uint8_t key[ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[ASCON_AEAD128_NONCE_LEN];
    uint8_t pt[16];
    uint8_t ad[8];
    uint8_t ciphertext[16];
    uint8_t tag[ASCON_AEAD128_TAG_LEN];

    generate_kat_pattern(key, sizeof(key), 0x00);
    generate_kat_pattern(nonce, sizeof(nonce), 0x10);
    generate_kat_pattern(pt, sizeof(pt), 0x20);
    generate_kat_pattern(ad, sizeof(ad), 0x30);

    static const uint8_t EXPECTED_CT[16] = {
        0xfa, 0xbe, 0x2c, 0xb1, 0xe7, 0xeb, 0xa6, 0x32,
        0x9a, 0x30, 0x08, 0x0f, 0x26, 0xe7, 0xdc, 0x72
    };
    static const uint8_t EXPECTED_TAG[ASCON_AEAD128_TAG_LEN] = {
        0x05, 0x3d, 0x4b, 0x06, 0x6b, 0x93, 0x97, 0x96,
        0x12, 0x5b, 0xeb, 0x58, 0x30, 0x09, 0xfe, 0x0d
    };

    int enc_res = ascon_aead128_encrypt(ciphertext, tag, pt, sizeof(pt), ad, sizeof(ad), nonce, key);
    TEST_ASSERT_EQUAL(ASCON_SUCCESS, enc_res);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_CT, ciphertext, sizeof(ciphertext));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_TAG, tag, ASCON_AEAD128_TAG_LEN);
}

/**
 * @brief Test poprawnosci szyfrowania i deszyfrowania (Round-Trip) na granicznych dlugosciach wiadomosci. Generujemy plaintext dla różnych długości. Szyfrujemy go, od razu deszyfrujemy i sprawdzamy czy się zgadza z pt
 */
static void test_aead128_roundtrip_boundary_lengths(void) {
    static const size_t TEST_LENGTHS[] = {0, 1, 15, 16, 17, 32, 65}; // wartości graniczne dla bloków -> blok=16B
    uint8_t key[ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[ASCON_AEAD128_NONCE_LEN];
    uint8_t ad[ASCON_AEAD128_RATE];

    generate_kat_pattern(key, sizeof(key), 0x00);
    generate_kat_pattern(nonce, sizeof(nonce), 0x10);
    generate_kat_pattern(ad, sizeof(ad), 0x30);

    for (size_t idx = 0; idx < sizeof(TEST_LENGTHS) / sizeof(TEST_LENGTHS[0]); ++idx) {
        size_t len = TEST_LENGTHS[idx];
        uint8_t pt[128];
        uint8_t ct[128];
        uint8_t dec[128];
        uint8_t tag[ASCON_AEAD128_TAG_LEN];

        generate_kat_pattern(pt, len, 0x20);

        // 1. Szyfrowanie
        int enc_res = ascon_aead128_encrypt(ct, tag, pt, len, ad, sizeof(ad), nonce, key);
        TEST_ASSERT_EQUAL(ASCON_SUCCESS, enc_res);

        // 2. Deszyfrowanie
        int dec_res = ascon_aead128_decrypt(dec, ct, len, tag, ad, sizeof(ad), nonce, key);
        TEST_ASSERT_EQUAL(ASCON_SUCCESS, dec_res);

        // 3. Asercja integralnosci tekstu odszyfrowanego
        if (len > 0) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(pt, dec, len);
        }
    }
}

/**
 * @brief Test negatywny: Zmiana 1 bitu w szyfrogramie powoduje odrzucenie tagu i wyzerowanie bufora plaintext.
 */
static void test_aead128_negative_tampered_ciphertext(void) {
    uint8_t key[ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[ASCON_AEAD128_NONCE_LEN];
    uint8_t pt[32];
    uint8_t ct[32];
    uint8_t tag[ASCON_AEAD128_TAG_LEN];
    uint8_t dec[32];

    generate_kat_pattern(key, sizeof(key), 0x00);
    generate_kat_pattern(nonce, sizeof(nonce), 0x10);
    generate_kat_pattern(pt, sizeof(pt), 0x20);
    memset(dec, 0xFF, sizeof(dec)); // wypełnienie bufora jedynkami

    // 1. Poprawne zaszyfrowanie 
    int enc_res = ascon_aead128_encrypt(ct, tag, pt, sizeof(pt), NULL, 0, nonce, key);
    TEST_ASSERT_EQUAL(ASCON_SUCCESS, enc_res);

    // 2. Celowe uszkodzenie szyfrogramu: odwrocenie najmlodszego bitu w 5 bajcie
    ct[5] ^= 0x01;

    // 3. Proba odszyfrowania zmodyfikowanego szyfrogramu
    int dec_res = ascon_aead128_decrypt(dec, ct, sizeof(ct), tag, NULL, 0, nonce, key);
    TEST_ASSERT_EQUAL(ASCON_TAG_MISMATCH, dec_res);

    // 4. Bufor tekstu jawnego musi zostac wyzerowany w przypadku bledu tagu
    static const uint8_t EXPECTED_ZERO[sizeof(dec)] = {0};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_ZERO, dec, sizeof(dec));
}

/**
 * @brief Test negatywny: Zmodyfikowany tag uwierzytelniajacy musi zostac odrzucony.
 */
static void test_aead128_negative_tampered_tag(void) {
    uint8_t key[ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[ASCON_AEAD128_NONCE_LEN];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t tag[ASCON_AEAD128_TAG_LEN];
    uint8_t dec[16];

    generate_kat_pattern(key, sizeof(key), 0x00);
    generate_kat_pattern(nonce, sizeof(nonce), 0x10);
    generate_kat_pattern(pt, sizeof(pt), 0x20);

    int enc_res = ascon_aead128_encrypt(ct, tag, pt, sizeof(pt), NULL, 0, nonce, key);
    TEST_ASSERT_EQUAL(ASCON_SUCCESS, enc_res);

    // Celowe uszkodzenie tagu uwierzytelniajacego 
    tag[0] ^= 0x80;

    int dec_res = ascon_aead128_decrypt(dec, ct, sizeof(ct), tag, NULL, 0, nonce, key);
    TEST_ASSERT_EQUAL(ASCON_TAG_MISMATCH, dec_res);
}

/**
 * @brief Test negatywny: Zmodyfikowane dane skojarzone (AD) musza skutkowac odrzuceniem tagu.
 */
static void test_aead128_negative_tampered_ad(void) {
    uint8_t key[ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[ASCON_AEAD128_NONCE_LEN];
    uint8_t ad[8];
    uint8_t tampered_ad[8];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t tag[ASCON_AEAD128_TAG_LEN];
    uint8_t dec[16];

    generate_kat_pattern(key, sizeof(key), 0x00);
    generate_kat_pattern(nonce, sizeof(nonce), 0x10);
    generate_kat_pattern(ad, sizeof(ad), 0x30);
    generate_kat_pattern(pt, sizeof(pt), 0x20);

    memcpy(tampered_ad, ad, sizeof(ad));
    tampered_ad[0] ^= 0x01;

    int enc_res = ascon_aead128_encrypt(ct, tag, pt, sizeof(pt), ad, sizeof(ad), nonce, key);
    TEST_ASSERT_EQUAL(ASCON_SUCCESS, enc_res);

    /* Odszyfrowanie z podmienionym naglowkiem AD */
    int dec_res = ascon_aead128_decrypt(dec, ct, sizeof(ct), tag, tampered_ad, sizeof(tampered_ad), nonce, key);
    TEST_ASSERT_EQUAL(ASCON_TAG_MISMATCH, dec_res);
}

/**
 * @brief Test weryfikacji tagu w stalym czasie (funkcji ascon_verify_tag_constant_time). Zapobiegnięcie ataku czasowego.
 */
static void test_aead128_constant_time_tag_verify(void) {
    uint8_t tag1[ASCON_AEAD128_TAG_LEN];
    uint8_t tag2[ASCON_AEAD128_TAG_LEN];

    generate_kat_pattern(tag1, sizeof(tag1), 0x00);
    memcpy(tag2, tag1, sizeof(tag2));

    /* 1. Tagi identyczne -> 0 */
    TEST_ASSERT_EQUAL(0, ascon_verify_tag_constant_time(tag1, tag2));

    /* 2. Roznica na pierwszej pozycji (bajt 0) -> nie 0 */
    tag2[0] ^= 0x01;
    TEST_ASSERT_NOT_EQUAL(0, ascon_verify_tag_constant_time(tag1, tag2));

    /* 3. Roznica na ostatniej pozycji (bajt 15) -> wynik niezerowy */
    tag2[0] = tag1[0];
    tag2[ASCON_AEAD128_TAG_LEN - 1] ^= 0x01;
    TEST_ASSERT_NOT_EQUAL(0, ascon_verify_tag_constant_time(tag1, tag2));
}

/**
 * @brief Test walidacji blednych parametrow (ochrona przed wskaznikami NULL).
 */
static void test_aead128_null_argument_guards(void) {
    uint8_t key[ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[ASCON_AEAD128_NONCE_LEN];
    uint8_t tag[ASCON_AEAD128_TAG_LEN];
    uint8_t buf[16];

    generate_kat_pattern(key, sizeof(key), 0x00);
    generate_kat_pattern(nonce, sizeof(nonce), 0x10);
    generate_kat_pattern(buf, sizeof(buf), 0x20);

    /* Szyfrowanie: brak wymaganych buforow klucza, nonce lub tagu */
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_encrypt(buf, tag, buf, sizeof(buf), NULL, 0, nonce, NULL));
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_encrypt(buf, tag, buf, sizeof(buf), NULL, 0, NULL, key));
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_encrypt(buf, NULL, buf, sizeof(buf), NULL, 0, nonce, key));

    /* Szyfrowanie: brak wskaznika na tekst lub szyfrogram przy dlugosci > 0 */
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_encrypt(buf, tag, NULL, sizeof(buf), NULL, 0, nonce, key));
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_encrypt(NULL, tag, buf, sizeof(buf), NULL, 0, nonce, key));

    /* Szyfrowanie: brak danych skojarzonych przy ad_len > 0 */
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_encrypt(buf, tag, buf, sizeof(buf), NULL, 8, nonce, key));

    /* Deszyfrowanie: brak wymaganych buforow klucza, nonce lub tagu */
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_decrypt(buf, buf, sizeof(buf), NULL, NULL, 0, nonce, key));
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_decrypt(buf, buf, sizeof(buf), tag, NULL, 0, NULL, key));
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_decrypt(buf, buf, sizeof(buf), tag, NULL, 0, nonce, NULL));

    /* Deszyfrowanie: brak wskaznika na tekst lub szyfrogram przy dlugosci > 0 */
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_decrypt(NULL, buf, sizeof(buf), tag, NULL, 0, nonce, key));
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT, ascon_aead128_decrypt(buf, NULL, sizeof(buf), tag, NULL, 0, nonce, key));

    /* Deszyfrowanie: brak danych skojarzonych przy ad_len > 0 */
    TEST_ASSERT_EQUAL(ASCON_INVALID_ARGUMENT,ascon_aead128_decrypt(buf, buf, sizeof(buf), tag, NULL, 8, nonce, key));
}

/**
 * @brief Funkcja agregujaca i uruchamiajaca caly modul testow AEAD.
 */
void run_aead_tests(void) {
    printf("\n--- Testy Ascon-AEAD128 ---\n");
    RUN_TEST(test_aead128_empty_pt_empty_ad_nist_kat);
    RUN_TEST(test_aead128_kat_with_ad_and_pt);
    RUN_TEST(test_aead128_roundtrip_boundary_lengths);
    RUN_TEST(test_aead128_negative_tampered_ciphertext);
    RUN_TEST(test_aead128_negative_tampered_tag);
    RUN_TEST(test_aead128_negative_tampered_ad);
    RUN_TEST(test_aead128_constant_time_tag_verify);
    RUN_TEST(test_aead128_null_argument_guards);
}
