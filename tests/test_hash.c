/**
 * @file test_hash.c
 * @brief Pakiet testow jednostkowych funkcji skrotu Ascon-Hash256 i Ascon-XOF128.
 * Wektory referencyjne pochodza bezposrednio z docs/test_reference/LWC_HASH_KAT_128_256.txt.
 */

#include "unity/unity.h"
#include "ascon/ascon_hash.h"
#include <string.h>

/**
 * @brief Wypelnia bufor sekwencyjnymi bajtami wg specyfikacji NIST KAT (0x00, 0x01, 0x02, ...).
 */
static void generate_kat_message(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)i;
    }
}

/**
 * @brief Weryfikacja dla pustej wiadomosci (0 bajtow).
 */
static void test_hash256_empty_message_nist_kat(void) {
    uint8_t digest[ASCON_HASH256_DIGEST_LEN];
    
    static const uint8_t EXPECTED_DIGEST[ASCON_HASH256_DIGEST_LEN] = {
        0x0b, 0x3b, 0xe5, 0x85, 0x0f, 0x2f, 0x6b, 0x98,
        0xca, 0xf2, 0x9f, 0x8f, 0xde, 0xa8, 0x9b, 0x64,
        0xa1, 0xfa, 0x70, 0xaa, 0x24, 0x9b, 0x8f, 0x83,
        0x9b, 0xd5, 0x3b, 0xaa, 0x30, 0x4d, 0x92, 0xb2
    };

    int res = ascon_hash256(digest, NULL, 0);
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_DIGEST, digest, ASCON_HASH256_DIGEST_LEN);
}

/**
 * @brief Weryfikacja dla krotkiej wiadomosci (4 bajty < rate 8 bajtow).
 */
static void test_hash256_short_message_nist(void) {
    uint8_t digest[ASCON_HASH256_DIGEST_LEN];
    uint8_t msg[4];
    generate_kat_message(msg, sizeof(msg));
    
    static const uint8_t EXPECTED_DIGEST[ASCON_HASH256_DIGEST_LEN] = {
        0xd7, 0xe4, 0xc7, 0xed, 0x9b, 0x8a, 0x32, 0x5c,
        0xd0, 0x8b, 0x9e, 0xf2, 0x59, 0xf8, 0x87, 0x70,
        0x54, 0xec, 0xd8, 0x30, 0x4f, 0xe1, 0xb2, 0xd7,
        0xfd, 0x84, 0x71, 0x37, 0xdf, 0x67, 0x27, 0xee
    };

    int res = ascon_hash256(digest, msg, sizeof(msg));
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_DIGEST, digest, ASCON_HASH256_DIGEST_LEN);
}

/**
 * @brief Test brzegowy: wiadomosc o dlugosci dokladnie 1 bloku rate (8 bajtow).
 * Źródło: docs/test_reference/LWC_HASH_KAT_128_256.txt, Count = 9 (linie 33-35).
 * Msg = 0001020304050607
 */
static void test_hash256_exact_single_block_boundary(void) {
    uint8_t digest[ASCON_HASH256_DIGEST_LEN];
    uint8_t msg[ASCON_HASH256_RATE];
    generate_kat_message(msg, sizeof(msg));
    
    static const uint8_t EXPECTED_DIGEST[ASCON_HASH256_DIGEST_LEN] = {
        0xb8, 0x8e, 0x49, 0x7a, 0xe8, 0xe6, 0xfb, 0x64,
        0x1b, 0x87, 0xef, 0x62, 0x2e, 0xb8, 0xf2, 0xfc,
        0xa0, 0xed, 0x95, 0x38, 0x3f, 0x7f, 0xfe, 0xbe,
        0x16, 0x7a, 0xcf, 0x10, 0x99, 0xba, 0x76, 0x4f
    };

    int res = ascon_hash256(digest, msg, sizeof(msg));
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_DIGEST, digest, ASCON_HASH256_DIGEST_LEN);
}

/**
 * @brief Weryfikacja dla wiadomosci wieloblokowej (43 bajty = 5 pelnych blokow 8B + 3 bajty).
 * Źródło: docs/test_reference/LWC_HASH_KAT_128_256.txt, Count = 44 (linie 173-176).
 * Msg = 00010203...2A
 */
static void test_hash256_multiblock_message(void) {
    uint8_t digest[ASCON_HASH256_DIGEST_LEN];
    uint8_t msg[43];
    generate_kat_message(msg, sizeof(msg));
    
    static const uint8_t EXPECTED_DIGEST[ASCON_HASH256_DIGEST_LEN] = {
        0xb4, 0xcb, 0x36, 0x55, 0xcf, 0xd0, 0xff, 0x0c,
        0xd9, 0x59, 0x0f, 0x6f, 0x24, 0xc5, 0xf3, 0x4c,
        0xf9, 0xb2, 0xc6, 0xfa, 0xc8, 0x77, 0xcd, 0x3e,
        0x03, 0x94, 0x25, 0x4d, 0x61, 0xac, 0xa9, 0x2c
    };

    int res = ascon_hash256(digest, msg, sizeof(msg));
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_DIGEST, digest, ASCON_HASH256_DIGEST_LEN);
}

/**
 * @brief Test Ascon-XOF128 dla pustej wiadomosci z wyjsciem 32 bajtow.
 */
static void test_xof128_empty_message(void) {
    uint8_t out[32];
    
    static const uint8_t EXPECTED_XOF[32] = {
        0x47, 0x3d, 0x5e, 0x61, 0x64, 0xf5, 0x8b, 0x39,
        0xdf, 0xd8, 0x4a, 0xac, 0xdb, 0x8a, 0xe4, 0x2e,
        0xc2, 0xd9, 0x1f, 0xed, 0x33, 0x38, 0x8e, 0xe0,
        0xd9, 0x60, 0xd9, 0xb3, 0x99, 0x32, 0x95, 0xc6
    };

    int res = ascon_xof128(out, sizeof(out), NULL, 0);
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED_XOF, out, sizeof(out));
}

/**
 * @brief Test spojnosci wyjscia XOF: wyjscie 16-bajtowe musi byc dokladnym prefiksem wyjscia 32-bajtowego.
 */
static void test_xof128_prefix_consistency(void) {
    uint8_t msg[32];
    generate_kat_message(msg, sizeof(msg));
    uint8_t out16[16];
    uint8_t out32[32];

    ascon_xof128(out16, sizeof(out16), msg, sizeof(msg));
    ascon_xof128(out32, sizeof(out32), msg, sizeof(msg));

    TEST_ASSERT_EQUAL_HEX8_ARRAY(out16, out32, sizeof(out16));
}

/**
 * @brief Test efektu lawinowego (Strict Avalanche Criterion - zmiana 1 bitu).
 */
static void test_hash256_avalanche_effect(void) {
    uint8_t in_a[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t in_b[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t dig_a[ASCON_HASH256_DIGEST_LEN];
    uint8_t dig_b[ASCON_HASH256_DIGEST_LEN];

    ascon_hash256(dig_a, in_a, sizeof(in_a));
    ascon_hash256(dig_b, in_b, sizeof(in_b));

    int bit_diff = 0;
    for (int i = 0; i < ASCON_HASH256_DIGEST_LEN; ++i) {
        uint8_t x = (uint8_t)(dig_a[i] ^ dig_b[i]); // XOR miedzy dwoma liczbami
        while (x) { // zliczanie 1 czyli różnicy między elementami
            bit_diff += (x & 1); 
            x >>= 1;
        }
    }
    
    TEST_ASSERT(bit_diff >= 80); // wiecej niz 31% bitøw musi byc zmieniona (ok. 50%)
}

/**
 * @brief Test walidacji blednych parametrow (ochrona przed próbą zapisania do NULL).
 */
static void test_hash256_null_argument_guards(void) {
    uint8_t dummy[4];
    generate_kat_message(dummy, sizeof(dummy));
    int res = ascon_hash256(NULL, dummy, sizeof(dummy));
    TEST_ASSERT_NOT_EQUAL(0, res);

    res = ascon_xof128(NULL, 16, dummy, sizeof(dummy));
    TEST_ASSERT_NOT_EQUAL(0, res);
}

/**
 * @brief Funkcja agregujaca i uruchamiajaca caly modul testow funkcji skrotu i XOF.
 */
void run_hash_tests(void) {
    printf("\n--- Testy Ascon-Hash256 i Ascon-XOF128 ---\n");
    RUN_TEST(test_hash256_empty_message_nist_kat);
    RUN_TEST(test_hash256_short_message_nist);
    RUN_TEST(test_hash256_exact_single_block_boundary);
    RUN_TEST(test_hash256_multiblock_message);
    RUN_TEST(test_xof128_empty_message);
    RUN_TEST(test_xof128_prefix_consistency);
    RUN_TEST(test_hash256_avalanche_effect);
    RUN_TEST(test_hash256_null_argument_guards);
}
