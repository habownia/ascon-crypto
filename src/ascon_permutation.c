/**
 * @file ascon_permutation.c
 * @brief Implementacja permutacji Ascon-p oraz funkcji pomocniczych (NIST SP 800-232).
 *
 * Odpowiedzialny: Jakub Duliban (Etap 2)
 *
 * Uwagi implementacyjne:
 *  - Stan trzymany jest jako 5 liczb uint64_t (reprezentacja calkowita, Dodatek A.2).
 *    Konwersja bajty <-> slowa jest jawnie little-endian, wiec kod dziala tak samo
 *    na PC (x86, LE), ESP8266/ESP32 (Xtensa/RISC-V, LE) i na maszynach big-endian.
 *  - S-box liczony jest metoda bit-slicing (operacje logiczne na calych slowach),
 *    a nie tablica: brak dostepu do pamieci zaleznego od danych = brak wycieku
 *    czasowego przez cache i mniejsze zuzycie pamieci na mikrokontrolerze.
 *  - Kod nie zawiera rozgalezien zaleznych od danych tajnych (stalo-czasowy).
 */

#include "ascon/ascon_permutation.h"

#include <string.h>

/* Tabela 5 NIST SP 800-232: const_0 .. const_15. */
const uint8_t ASCON_ROUND_CONSTANTS[ASCON_MAX_ROUNDS] = {
    0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3,
    0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

/* Rotacja w prawo 64-bitowego slowa (operacja ">>>" ze standardu, Tabela 4).
 * Wywolywana wylacznie ze stalymi 0 < n < 64, wiec nie ma przesuniecia o 64 (UB). */
static inline uint64_t rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64u - n));
}



/* Operacje na stanie */

void ascon_state_init(ascon_state_t *s)
{
    if (s == NULL) {
        return;
    }
    for (size_t i = 0; i < ASCON_STATE_WORDS; ++i) {
        s->x[i] = 0;
    }
}

void ascon_secure_zero(void *buf, size_t len)
{
    /* volatile wymusza faktyczny zapis kazdego bajtu - optymalizator nie moze
     * usunac zerowania pamieci, ktora "nie jest juz pozniej czytana". */
    volatile uint8_t *p = (volatile uint8_t *)buf;
    if (p == NULL) {
        return;
    }
    while (len--) {
        *p++ = 0;
    }
}

void ascon_state_clean(ascon_state_t *s)
{
    if (s == NULL) {
        return;
    }
    ascon_secure_zero(s, sizeof(*s));
}



/* Konwersje little-endian i padding */

uint64_t ascon_load64_le(const uint8_t *bytes)
{
    return  (uint64_t)bytes[0]
         | ((uint64_t)bytes[1] << 8)
         | ((uint64_t)bytes[2] << 16)
         | ((uint64_t)bytes[3] << 24)
         | ((uint64_t)bytes[4] << 32)
         | ((uint64_t)bytes[5] << 40)
         | ((uint64_t)bytes[6] << 48)
         | ((uint64_t)bytes[7] << 56);
}

void ascon_store64_le(uint8_t *bytes, uint64_t val)
{
    bytes[0] = (uint8_t)(val);
    bytes[1] = (uint8_t)(val >> 8);
    bytes[2] = (uint8_t)(val >> 16);
    bytes[3] = (uint8_t)(val >> 24);
    bytes[4] = (uint8_t)(val >> 32);
    bytes[5] = (uint8_t)(val >> 40);
    bytes[6] = (uint8_t)(val >> 48);
    bytes[7] = (uint8_t)(val >> 56);
}

uint64_t ascon_load_bytes_le(const uint8_t *bytes, size_t len)
{
    uint64_t x = 0;
    if (len > 8) {
        len = 8;
    }
    for (size_t i = 0; i < len; ++i) {
        x |= (uint64_t)bytes[i] << (8u * i);
    }
    return x;
}

void ascon_store_bytes_le(uint8_t *bytes, uint64_t val, size_t len)
{
    if (len > 8) {
        len = 8;
    }
    for (size_t i = 0; i < len; ++i) {
        bytes[i] = (uint8_t)(val >> (8u * i));
    }
}

uint64_t ascon_pad(size_t len)
{
    /* Dla len >= 8 blok jest pelny i padding trafia do nastepnego slowa,
     * wiec w tym slowie nie ma czego ustawiac (unikamy tez przesuniecia o 64). */
    if (len >= 8) {
        return 0;
    }
    return (uint64_t)0x01 << (8u * len);
}



/* Warstwy rundy */

void ascon_constant_layer(ascon_state_t *s, uint8_t round_const)
{
    /* Wzor (4): S2 = S2 xor c_i. Stala ma 56 zerowych starszych bitow. */
    s->x[2] ^= (uint64_t)round_const;
}

void ascon_substitution_layer(ascon_state_t *s)
{
    /*
     * Bit-sliced S-box (wzory 7 / Figure 3). Kazde slowo x_k przechowuje k-ty bit
     * wejscia dla wszystkich 64 kolumn naraz. Sekwencja odpowiada obwodowi z
     * Figure 3: warstwa XOR wejsciowa, warstwa chi (~a & b), warstwa XOR wyjsciowa
     * i negacja x2 (stala "1" w rownaniu na y2).
     */
    uint64_t x0 = s->x[0];
    uint64_t x1 = s->x[1];
    uint64_t x2 = s->x[2];
    uint64_t x3 = s->x[3];
    uint64_t x4 = s->x[4];
    uint64_t t0, t1, t2, t3, t4;

    /* Warstwa wejsciowa */
    x0 ^= x4;
    x4 ^= x3;
    x2 ^= x1;

    /* Warstwa nieliniowa */
    t0 = ~x0 & x1;
    t1 = ~x1 & x2;
    t2 = ~x2 & x3;
    t3 = ~x3 & x4;
    t4 = ~x4 & x0;
    x0 ^= t1;
    x1 ^= t2;
    x2 ^= t3;
    x3 ^= t4;
    x4 ^= t0;

    /* Warstwa wyjsciowa */
    x1 ^= x0;
    x0 ^= x4;
    x3 ^= x2;
    x2 = ~x2;

    s->x[0] = x0;
    s->x[1] = x1;
    s->x[2] = x2;
    s->x[3] = x3;
    s->x[4] = x4;
}

void ascon_linear_layer(ascon_state_t *s)
{
    /* Wzory (8)-(12) */
    s->x[0] ^= rotr64(s->x[0], 19) ^ rotr64(s->x[0], 28);
    s->x[1] ^= rotr64(s->x[1], 61) ^ rotr64(s->x[1], 39);
    s->x[2] ^= rotr64(s->x[2],  1) ^ rotr64(s->x[2],  6);
    s->x[3] ^= rotr64(s->x[3], 10) ^ rotr64(s->x[3], 17);
    s->x[4] ^= rotr64(s->x[4],  7) ^ rotr64(s->x[4], 41);
}

void ascon_permutation_round(ascon_state_t *s, uint8_t round_const)
{
    /* Wzor (1): p = p_L o p_S o p_C */
    ascon_constant_layer(s, round_const);
    ascon_substitution_layer(s);
    ascon_linear_layer(s);
}
/* Permutacje */

void ascon_p(ascon_state_t *s, unsigned int rounds)
{
    if (s == NULL || rounds == 0 || rounds > ASCON_MAX_ROUNDS) {
        return;
    }
    /* Wzor (3): c_i = const_{16 - rounds + i} dla i = 0 .. rounds-1 */
    for (unsigned int i = ASCON_MAX_ROUNDS - rounds; i < ASCON_MAX_ROUNDS; ++i) {
        ascon_permutation_round(s, ASCON_ROUND_CONSTANTS[i]);
    }
}

void ascon_p12(ascon_state_t *s)
{
    ascon_p(s, 12);
}

void ascon_p8(ascon_state_t *s)
{
    ascon_p(s, 8);
}
