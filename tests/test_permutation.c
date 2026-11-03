/**
 * @file test_permutation.c
 * @brief Pakiet testow jednostkowych weryfikujacych permutacje Ascon-p wg NIST SP 800-232.
 * 
 */

#include "unity/unity.h"
#include "ascon/ascon_permutation.h"

/* Inicjalizacja i czyszczenie przed/po kazdym tescie Unity */
void setUp(void) {}
void tearDown(void) {}

/**
 * @brief Test inicjalizacji oraz bezpiecznego czyszczenia stanu w pamieci RAM.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja 3.1 "Internal State" (strona 8)
 * - Sekcja 4.3 "AEAD Requirements" (strona 19: wymog bezpiecznego niszczenia
 *   wrażliwych danych klucza i stanu wewnetrznego po zakonczeniu operacji)
 * 
 * Metodyka:
 * - Wypelniamy stan 's' losowymi danymi testowymi (tzw. "canary values").
 * - Wywolujemy funkcje 'ascon_state_clean'.
 * - Asercja sprawdza, czy kazde z 5 slow (S0..S4) zostalo bezwzglednie wyzerowane,
 *   co zapobiega wyciekom informacji o kluczu po wyjsciu z procedur kryptograficznych.
 */
static void test_state_init_and_clean(void) {
    ascon_state_t s;
    
    /* Krok 1: Wypelnienie stanu niezerowymi wartosciami kontrolnymi */
    s.x[0] = 0x1122334455667788ULL;
    s.x[1] = 0x99AABBCCDDEEFF00ULL;
    s.x[2] = 0xDEADBEEFCAFEBABEULL;
    s.x[3] = 0x0123456789ABCDEFULL;
    s.x[4] = 0xFEDCBA9876543210ULL;

    /* Krok 2: Bezpieczne czyszczenie stanu */
    ascon_state_clean(&s);

    /* Krok 3: Sprawdzenie kazdego z 5 64-bitowych slow stanu czy jest wyzerowane */
    TEST_ASSERT_EQUAL_HEX64(0ULL, s.x[0]);
    TEST_ASSERT_EQUAL_HEX64(0ULL, s.x[1]);
    TEST_ASSERT_EQUAL_HEX64(0ULL, s.x[2]);
    TEST_ASSERT_EQUAL_HEX64(0ULL, s.x[3]);
    TEST_ASSERT_EQUAL_HEX64(0ULL, s.x[4]);
}

/**
 * @brief Test konwersji Little-Endian miedzy ciagiem bajtow a 64-bitowym slowem uint64_t.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Dodatek A.1 "Conversion Functions" (strony 35-36)
 * - Dodatek A.2 "Implementing with Integers" (Tabela 10, Figure 9, Figure 10)
 * 
 * Wyjasnienie matematyczne i sprzetowe:
 * Slowa stanu Ascona sa mapowane w formacie Little-Endian. Oznacza to, ze:
 * - Bajt o indeksie 0 w pamieci (0x00) jest najmlodszym bajtem liczby (LSB, bity 0..7).
 * - Bajt o indeksie 7 w pamieci (0x07) jest najstarszym bajtem liczby (MSB, bity 56..63).
 * W rejestrze 64-bitowym daje to liczbe 0x0706050403020100ULL.
 * 
 * Test sprawdza ladowanie (ascon_load64_le) oraz zapis powrotny do pamieci (ascon_store64_le).
 */
static void test_little_endian_helpers(void) {
    /* 8 bajtow ulozonych sekwencyjnie w pamieci */
    uint8_t bytes[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    
    /* 1. Sprawdzenie ladowania: bytes -> uint64_t */
    uint64_t val = ascon_load64_le(bytes);
    TEST_ASSERT_EQUAL_HEX64(0x0706050403020100ULL, val);

    /* 2. Sprawdzenie zapisu powrotnego: uint64_t -> out[] */
    uint8_t out[8] = {0};
    ascon_store64_le(out, val);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(bytes, out, 8);
}

/**
 * @brief Test zgodnosci 5-bitowej warstwy nieliniowej S-box dla wszystkich 32 wejsc (0..31).
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja 3.3 "Substitution Layer p_S" (strony 9-10)
 * - Tabela 6 "Lookup table representation of SBOX" (strona 10)
 * - Schemat logiczny bramkowy: Figure 3 "Circuit representation of the 5-bit S-box" (strona 10)
 * 
 * Zasada dzialania S-boxa w Asconie:
 * Ascon operuje na 5-bitowych wycinkach stanu (tzw. "bit-sliced"). Dla danej pozycji bitowej 'i':
 * - Bit wejsciowy 4 pochodzi ze slowa S0[i]
 * - Bit wejsciowy 3 pochodzi ze slowa S1[i]
 * - Bit wejsciowy 2 pochodzi ze slowa S2[i]
 * - Bit wejsciowy 1 pochodzi ze slowa S3[i]
 * - Bit wejsciowy 0 pochodzi ze slowa S4[i]
 * 
 * Przebieg testu:
 * Dla kazdej liczby od 0 do 31 ustawiamy odpowiednie bity na pozycji 0 w stanie,
 * a nastepnie wykonujemy jedna runde permutacji ze stala rundowa rowna 0.
 * W ten sposob weryfikujemy, czy wyjscie S-boxa pokrywa sie z oficjalna Tabela 6 NIST.
 */
static void test_sbox_table6_conformance(void) {
    /* Oficjalna tabela podstawieniowa S-box z Tabeli 6 w NIST SP 800-232 */
    static const uint8_t EXPECTED_SBOX[32] = {
        0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02,
        0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
        0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,
        0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17
    };

    /* Sprawdzamy kazda z 32 mozliwych 5-bitowych kombinacji wejsciowych */
    for (uint32_t val = 0; val < 32; ++val) {
        ascon_state_t s;
        ascon_state_init(&s);

        /* Ustawiamy bit 0 kazdego ze slow S0..S4 przesuwając bitowo val o n bitów  */
        s.x[0] = (val >> 4) & 1; /* MSB wejscia 5-bitowego */
        s.x[1] = (val >> 3) & 1;
        s.x[2] = (val >> 2) & 1;
        s.x[3] = (val >> 1) & 1;
        s.x[4] = (val >> 0) & 1; /* LSB wejscia 5-bitowego */

        /* Wykonanie pojedynczej rundy ze stala 0 (warstwa p_C dodaje 0, p_S aplikuje S-box) */
        ascon_permutation_round(&s, 0);

        /* Pobranie bitu 0 z kazdego slowa po przejsciu przez runde */
        uint8_t out_val = (uint8_t)(((s.x[0] & 1) << 4) |
                                    ((s.x[1] & 1) << 3) |
                                    ((s.x[2] & 1) << 2) |
                                    ((s.x[3] & 1) << 1) |
                                    ((s.x[4] & 1) << 0));

        /* Weryfikacja ze wzorcem z Tabeli 6 */
        TEST_ASSERT_EQUAL_HEX8(EXPECTED_SBOX[val], out_val);
    }
}

/**
 * @brief Test weryfikujacy stan posredni po permutacji p[12] dla Ascon-Hash256.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja 5.1 "Specification of Ascon-Hash256" (Algorithm 5, wzory 54-55)
 * - Tabela 14 "Initial values as hexadecimal integers" (strona 41, IV = 0x0000080100cc0002)
 * - Tabela 12 "Precomputed initialization phase values" (strona 40)
 * 
 * Cel testu:
 * Zgodnie ze standardem, stan poczatkowy sklada sie z 64-bitowego wektora IV oraz 256 zer.
 * Nastepnie wykonywana jest 12-rundowa permutacja p[12].
 * Wynik w rejestrach S0..S4 po permutacji musi byc dokladnie zgodny ze stanem prekomputowanym opublikowanym w Tabeli 12 specyfikacji NIST.
 */
static void test_p12_hash256_initialization_table12(void) {
    ascon_state_t s;
    ascon_state_init(&s);

    /* 1. Inicjalizacja stanu: S0 = IV, S1..S4 = 0 */
    s.x[0] = 0x0000080100cc0002ULL;

    /* 2. Uruchomienie pelnej 12-rundowej permutacji Ascon-p[12] */
    ascon_p12(&s);

    /* 3. Weryfikacja ze stanem prekomputowanym z Tabeli 12 (NIST SP 800-232, strona 40) */
    TEST_ASSERT_EQUAL_HEX64(0x9b1e5494e934d681ULL, s.x[0]);
    TEST_ASSERT_EQUAL_HEX64(0x4bc3a01e333751d2ULL, s.x[1]);
    TEST_ASSERT_EQUAL_HEX64(0xae65396c6b34b81aULL, s.x[2]);
    TEST_ASSERT_EQUAL_HEX64(0x3c7fd4a4d56a4db3ULL, s.x[3]);
    TEST_ASSERT_EQUAL_HEX64(0x1a5c464906c5976dULL, s.x[4]);
}

/**
 * @brief Test weryfikujacy stan posredni po permutacji p[12] dla Ascon-XOF128.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja 5.2 "Specification of Ascon-XOF128" (Algorithm 6, wzory 66-67)
 * - Tabela 14 "Initial values" (IV = 0x0000080000cc0003)
 * - Tabela 12 "Precomputed initialization phase values" (strona 40)
 */
static void test_p12_xof128_initialization_table12(void) {
    ascon_state_t s;
    ascon_state_init(&s);

    /* 1. Inicjalizacja stanu wektorem IV dla XOF128 */
    s.x[0] = 0x0000080000cc0003ULL;

    /* 2. Wykonanie permutacji p[12] */
    ascon_p12(&s);

    /* 3. Asercja wartosci slow z Tabeli 12 */
    TEST_ASSERT_EQUAL_HEX64(0xda82ce768d9447ebULL, s.x[0]);
    TEST_ASSERT_EQUAL_HEX64(0xcc7ce6c75f1ef969ULL, s.x[1]);
    TEST_ASSERT_EQUAL_HEX64(0xe7508fd780085631ULL, s.x[2]);
    TEST_ASSERT_EQUAL_HEX64(0x0ee0ea53416b58ccULL, s.x[3]);
    TEST_ASSERT_EQUAL_HEX64(0xe0547524db6f0bdeULL, s.x[4]);
}

/**
 * @brief Test weryfikujacy stan posredni po permutacji p[12] dla Ascon-CXOF128.
 * 
 * Odniesienie do standardu NIST SP 800-232:
 * - Sekcja 5.3 "Specification of Ascon-CXOF128" (Algorithm 7)
 * - Tabela 14 "Initial values" (IV = 0x0000080000cc0004)
 * - Tabela 12 "Precomputed initialization phase values" (strona 40)
 */
static void test_p12_cxof128_initialization_table12(void) {
    ascon_state_t s;
    ascon_state_init(&s);

    /* 1. Inicjalizacja stanu wektorem IV dla CXOF128 */
    s.x[0] = 0x0000080000cc0004ULL;

    /* 2. Wykonanie permutacji p[12] */
    ascon_p12(&s);

    /* 3. Asercja wartosci slow z Tabeli 12 */
    TEST_ASSERT_EQUAL_HEX64(0x675527c2a0e8de03ULL, s.x[0]);
    TEST_ASSERT_EQUAL_HEX64(0x43d12d7dc0377bbcULL, s.x[1]);
    TEST_ASSERT_EQUAL_HEX64(0xe9901dec426e81b5ULL, s.x[2]);
    TEST_ASSERT_EQUAL_HEX64(0x2ab14907720780b6ULL, s.x[3]);
    TEST_ASSERT_EQUAL_HEX64(0x8f3f1d02d432bc46ULL, s.x[4]);
}

/**
 * @brief Test funkcji ascon_pad(len) wg Tabeli 11 NIST SP 800-232.
 * 
 * Odniesienie do standardu:
 * - Algorytm 2 "pad(X, r)" (Sekcja 2)
 * - Tabela 11 "Examples of padding an unsigned integer x to a 64-bit block" (strona 38)
 */
static void test_ascon_pad_table11(void) {
    /* Dla dlugosci len od 0 do 7 bajtow bit 0x01 jest wstawiany na pozycji 8*len */
    TEST_ASSERT_EQUAL_HEX64(0x0000000000000001ULL, ascon_pad(0));
    TEST_ASSERT_EQUAL_HEX64(0x0000000000000100ULL, ascon_pad(1));
    TEST_ASSERT_EQUAL_HEX64(0x0000000000010000ULL, ascon_pad(2));
    TEST_ASSERT_EQUAL_HEX64(0x0000000001000000ULL, ascon_pad(3));
    TEST_ASSERT_EQUAL_HEX64(0x0000000100000000ULL, ascon_pad(4));
    TEST_ASSERT_EQUAL_HEX64(0x0000010000000000ULL, ascon_pad(5));
    TEST_ASSERT_EQUAL_HEX64(0x0001000000000000ULL, ascon_pad(6));
    TEST_ASSERT_EQUAL_HEX64(0x0100000000000000ULL, ascon_pad(7));
    /* Dla pelnego bloku (len >= 8) padding trafia do kolejnego bloku, funkcja zwraca 0 */
    TEST_ASSERT_EQUAL_HEX64(0ULL, ascon_pad(8));
}

/**
 * @brief Test ladowania i zapisu czesciowych blokow (ascon_load_bytes_le i ascon_store_bytes_le).
 */
static void test_ascon_load_store_bytes_le(void) {
    uint8_t raw[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
    uint8_t out[8] = {0};

    /* Ladowanie 0 bajtow -> 0 */
    TEST_ASSERT_EQUAL_HEX64(0ULL, ascon_load_bytes_le(raw, 0));

    /* Ladowanie 3 bajtow -> 0x0000000000CCBBAA */
    TEST_ASSERT_EQUAL_HEX64(0x0000000000CCBBAAULL, ascon_load_bytes_le(raw, 3));

    /* Zapis 3 bajtow */
    ascon_store_bytes_le(out, 0x0000000000CCBBAAULL, 3);
    TEST_ASSERT_EQUAL_HEX8(0xAA, out[0]);
    TEST_ASSERT_EQUAL_HEX8(0xBB, out[1]);
    TEST_ASSERT_EQUAL_HEX8(0xCC, out[2]);
    TEST_ASSERT_EQUAL_HEX8(0x00, out[3]);
}

/**
 * @brief Test bezpiecznego czyszczenia dowolnego bufora (ascon_secure_zero).
 */
static void test_ascon_secure_zero(void) {
    uint8_t buf[16];
    memset(buf, 0x5A, sizeof(buf)); // wypełnienie śmieciami
    ascon_secure_zero(buf, sizeof(buf));

    for (size_t i = 0; i < sizeof(buf); ++i) {
        TEST_ASSERT_EQUAL_HEX8(0x00, buf[i]);
    }
}

/**
 * @brief Test warstwy dodawania stalej p_C (ascon_constant_layer).
 */
static void test_ascon_constant_layer(void) {
    ascon_state_t s;
    ascon_state_init(&s);
    s.x[2] = 0x123456789ABCDEF0ULL; // liczba testowa

    ascon_constant_layer(&s, 0x3c); //0x3c -> ASCON_ROUND_CONSTANTS[0]
    TEST_ASSERT_EQUAL_HEX64(0x123456789ABCDEF0ULL ^ 0x3cULL, s.x[2]); // XOR losowej wartości
    /* Pozostale slowa musza pozostac nienaruszone */
    TEST_ASSERT_EQUAL_HEX64(0ULL, s.x[0]);
    TEST_ASSERT_EQUAL_HEX64(0ULL, s.x[1]);
    TEST_ASSERT_EQUAL_HEX64(0ULL, s.x[3]);
    TEST_ASSERT_EQUAL_HEX64(0ULL, s.x[4]);
}

/**
 * @brief Funkcja agregujaca i uruchamiajaca caly modul testow permutacji.
 */
void run_permutation_tests(void) {
    printf("\n--- Testy Permutacji Ascon-p (NIST SP 800-232) ---\n");
    RUN_TEST(test_state_init_and_clean);
    RUN_TEST(test_ascon_secure_zero);
    RUN_TEST(test_little_endian_helpers);
    RUN_TEST(test_ascon_load_store_bytes_le);
    RUN_TEST(test_ascon_pad_table11);
    RUN_TEST(test_ascon_constant_layer);
    RUN_TEST(test_sbox_table6_conformance);
    RUN_TEST(test_p12_hash256_initialization_table12);
    RUN_TEST(test_p12_xof128_initialization_table12);
    RUN_TEST(test_p12_cxof128_initialization_table12);
}

