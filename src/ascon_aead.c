/**
 * @file ascon_aead.c
 * @brief Implementacja Ascon-AEAD128 (Algorithm 3 i 4) wraz z opcjami z Sekcji 4.2,
 *        NIST SP 800-232.
 *
 * Odpowiedzialny: Wojciech Aleksander (Etap 2)
 *
 * Budowa (konstrukcja duplex, Figure 5 i Figure 6):
 *  - stan 320 bitow = czesc "rate" (S0, S1 - 128 bitow) + czesc "capacity" (S2..S4),
 *  - inicjalizacja: S = IV || K || N, p[12], S = S xor (0^192 || K),
 *  - dane skojarzone (AD) i tekst jawny sa przetwarzane blokami po 16 bajtow,
 *    po kazdym pelnym bloku wykonywana jest permutacja p[8],
 *  - finalizacja: S = S xor (0^128 || K || 0^64), p[12], T = S[192:319] xor K.
 *
 * Uwagi:
 *  - Klucz, nonce i dane laduja sie do stanu w porzadku little-endian (Dodatek A.2),
 *    wiec S[0:63] = load64_le(bajty 0..7), S[64:127] = load64_le(bajty 8..15).
 *  - Padding ostatniego bloku to ascon_pad(len) = 0x01 << (8 * len) w slowie,
 *    w ktorym konczy sie dane (Table 11).
 *  - Szyfrowanie i deszyfrowanie dzialaja tez "w miejscu" (ciphertext == plaintext):
 *    kazde slowo jest najpierw czytane, a dopiero potem zapisywane.
 *  - Tag porownywany jest w czasie stalym, a przy blednym tagu bufor z tekstem
 *    jawnym jest zerowany - niezweryfikowane dane nie moga wyjsc poza funkcje.
 *  - Stan, kopie klucza i tag pomocniczy sa na koncu bezpiecznie zerowane.
 *  - Brak alokacji pamieci: tylko stan (40 B) i kilka slow na stosie (ESP8266/ESP32).
 */

#include "ascon/ascon_aead.h"
#include "ascon/ascon_permutation.h"

/* Bit separacji domen 0^319 || 1 - najstarszy bit slowa S4 (wzory 22 i 40). */
#define ASCON_DOMAIN_SEPARATION 0x8000000000000000ULL

/* Klucz w postaci dwoch slow 64-bitowych: K = K0 || K1. */
typedef struct {
    uint64_t k0;
    uint64_t k1;
} aead_key_t;

/* Fazy algorytmu (wspolne dla szyfrowania i deszyfrowania) */

/**
 * Inicjalizacja stanu. Szyfrowanie: wzory (15)-(17). Deszyfrowanie: wzory (33)-(35).
 *
 * S = IV || K || N, nastepnie S = p[12](S) i S = S xor (0^192 || K).
 */
static void aead_initialize(ascon_state_t *s, const aead_key_t *k,
                            const uint8_t nonce[ASCON_AEAD128_NONCE_LEN])
{
    s->x[0] = ASCON_AEAD128_IV;
    s->x[1] = k->k0;
    s->x[2] = k->k1;
    s->x[3] = ascon_load64_le(nonce);
    s->x[4] = ascon_load64_le(nonce + 8);

    ascon_p12(s);

    s->x[3] ^= k->k0;
    s->x[4] ^= k->k1;
}

/**
 * Przetwarzanie danych skojarzonych. Szyfrowanie: wzory (18)-(22).
 * Deszyfrowanie: wzory (36)-(40).
 *
 * Gdy |A| > 0: A jest dzielone na bloki 128-bitowe, ostatni blok jest dopelniany
 * paddingiem 10* (zawsze - takze gdy |A| jest wielokrotnoscia 16 bajtow; wtedy
 * ostatni blok to sam padding). Po kazdym bloku: S[0:127] ^= A_i, S = p[8](S).
 * Gdy |A| = 0: blok AD jest pomijany calkowicie (nie ma nawet bloku z paddingiem).
 * W obu przypadkach na koncu S = S xor (0^319 || 1).
 */
static void aead_absorb_ad(ascon_state_t *s, const uint8_t *ad, size_t ad_len)
{
    if (ad_len > 0) {
        /* Pelne bloki 16-bajtowe. */
        while (ad_len >= ASCON_AEAD128_RATE) {
            s->x[0] ^= ascon_load64_le(ad);
            s->x[1] ^= ascon_load64_le(ad + 8);
            ascon_p8(s);
            ad += ASCON_AEAD128_RATE;
            ad_len -= ASCON_AEAD128_RATE;
        }

        /* Ostatni blok: 0..15 pozostalych bajtow + padding. */
        if (ad_len < 8) {
            s->x[0] ^= ascon_load_bytes_le(ad, ad_len) ^ ascon_pad(ad_len);
        } else {
            s->x[0] ^= ascon_load64_le(ad);
            s->x[1] ^= ascon_load_bytes_le(ad + 8, ad_len - 8) ^ ascon_pad(ad_len - 8);
        }
        ascon_p8(s);
    }

    s->x[4] ^= ASCON_DOMAIN_SEPARATION;
}

/**
 * Szyfrowanie tekstu jawnego. Wzory (23)-(29).
 *
 * Dla kazdego pelnego bloku: S[0:127] ^= P_i, C_i = S[0:127], S = p[8](S).
 * Ostatni blok (0..15 bajtow, moze byc pusty): S[0:127] ^= pad(P_n),
 * C_n = S[0:l-1] - bez permutacji, bo po nim nastepuje finalizacja.
 */
static void aead_encrypt_data(ascon_state_t *s, uint8_t *out,
                              const uint8_t *in, size_t len)
{
    while (len >= ASCON_AEAD128_RATE) {
        s->x[0] ^= ascon_load64_le(in);
        s->x[1] ^= ascon_load64_le(in + 8);
        ascon_store64_le(out, s->x[0]);
        ascon_store64_le(out + 8, s->x[1]);
        ascon_p8(s);
        in += ASCON_AEAD128_RATE;
        out += ASCON_AEAD128_RATE;
        len -= ASCON_AEAD128_RATE;
    }

    if (len < 8) {
        s->x[0] ^= ascon_load_bytes_le(in, len) ^ ascon_pad(len);
        ascon_store_bytes_le(out, s->x[0], len);
    } else {
        s->x[0] ^= ascon_load64_le(in);
        s->x[1] ^= ascon_load_bytes_le(in + 8, len - 8) ^ ascon_pad(len - 8);
        ascon_store64_le(out, s->x[0]);
        ascon_store_bytes_le(out + 8, s->x[1], len - 8);
    }
}

/**
 * Podmiana najmlodszych len bajtow slowa stanu na bajty szyfrogramu (len = 0..7)
 * oraz dolozenie bitu paddingu tuz za nimi - wzory (46)-(47) dla jednego slowa.
 *
 * Maska len bajtow to ascon_pad(len) - 1 (dla len = 0 maska jest pusta).
 */
static uint64_t aead_replace_bytes(uint64_t word, uint64_t c, size_t len)
{
    uint64_t mask = ascon_pad(len) - 1u;
    return ((word & ~mask) | c) ^ ascon_pad(len);
}

/**
 * Deszyfrowanie szyfrogramu. Wzory (41)-(48).
 *
 * Dla kazdego pelnego bloku: P_i = S[0:127] xor C_i, S[0:127] = C_i, S = p[8](S).
 * Ostatni blok (dlugosc l = 0..15 bajtow): P_n = S[0:l-1] xor C_n,
 * S[0:l-1] = C_n, S[l:127] ^= (1 || 0^(127-l)).
 * Slowa szyfrogramu sa czytane przed zapisem tekstu jawnego (praca w miejscu).
 */
static void aead_decrypt_data(ascon_state_t *s, uint8_t *out,
                              const uint8_t *in, size_t len)
{
    uint64_t c0;
    uint64_t c1;

    while (len >= ASCON_AEAD128_RATE) {
        c0 = ascon_load64_le(in);
        c1 = ascon_load64_le(in + 8);
        ascon_store64_le(out, s->x[0] ^ c0);
        ascon_store64_le(out + 8, s->x[1] ^ c1);
        s->x[0] = c0;
        s->x[1] = c1;
        ascon_p8(s);
        in += ASCON_AEAD128_RATE;
        out += ASCON_AEAD128_RATE;
        len -= ASCON_AEAD128_RATE;
    }

    if (len < 8) {
        c0 = ascon_load_bytes_le(in, len);
        ascon_store_bytes_le(out, s->x[0] ^ c0, len);
        s->x[0] = aead_replace_bytes(s->x[0], c0, len);
    } else {
        c0 = ascon_load64_le(in);
        c1 = ascon_load_bytes_le(in + 8, len - 8);
        ascon_store64_le(out, s->x[0] ^ c0);
        ascon_store_bytes_le(out + 8, s->x[1] ^ c1, len - 8);
        s->x[0] = c0;
        s->x[1] = aead_replace_bytes(s->x[1], c1, len - 8);
    }
}

/**
 * Finalizacja i obliczenie pelnego, 128-bitowego tagu.
 * Szyfrowanie: wzory (30)-(32). Deszyfrowanie: wzory (49)-(51).
 *
 * S = S xor (0^128 || K || 0^64), S = p[12](S), T = S[192:319] xor K.
 */
static void aead_finalize(ascon_state_t *s, const aead_key_t *k,
                          uint8_t tag[ASCON_AEAD128_TAG_LEN])
{
    s->x[2] ^= k->k0;
    s->x[3] ^= k->k1;

    ascon_p12(s);

    ascon_store64_le(tag, s->x[3] ^ k->k0);
    ascon_store64_le(tag + 8, s->x[4] ^ k->k1);
}

/* Porownanie w czasie stalym: XOR wszystkich bajtow i suma logiczna roznic,
 * bez wczesnego wyjscia z petli - czas nie zalezy od miejsca pierwszej roznicy. */
static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (int)diff;
}

/* Rdzen szyfrowania i deszyfrowania (tag o dlugosci 4..16 bajtow) */

static int aead_args_valid(const void *out, const void *in, size_t len,
                           const void *ad, size_t ad_len,
                           const void *tag, size_t tag_len,
                           const void *nonce, const void *key)
{
    if (nonce == NULL || key == NULL || tag == NULL) {
        return 0;
    }
    if (len != 0 && (out == NULL || in == NULL)) {
        return 0;
    }
    if (ad_len != 0 && ad == NULL) {
        return 0;
    }
    if (tag_len < ASCON_AEAD128_MIN_TAG_LEN || tag_len > ASCON_AEAD128_TAG_LEN) {
        return 0;
    }
    return 1;
}

static int aead_encrypt(uint8_t *ciphertext, uint8_t *tag, size_t tag_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        const uint8_t *assoc_data, size_t assoc_data_len,
                        const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                        const uint8_t key[ASCON_AEAD128_KEY_LEN])
{
    ascon_state_t s;
    aead_key_t k;
    uint8_t full_tag[ASCON_AEAD128_TAG_LEN];

    if (!aead_args_valid(ciphertext, plaintext, plaintext_len,
                         assoc_data, assoc_data_len, tag, tag_len, nonce, key)) {
        return ASCON_INVALID_ARGUMENT;
    }

    k.k0 = ascon_load64_le(key);
    k.k1 = ascon_load64_le(key + 8);

    aead_initialize(&s, &k, nonce);
    aead_absorb_ad(&s, assoc_data, assoc_data_len);
    aead_encrypt_data(&s, ciphertext, plaintext, plaintext_len);
    aead_finalize(&s, &k, full_tag);

    /* Sekcja 4.2.1: tag skrocony to lambda pierwszych (najlewszych) bitow T. */
    for (size_t i = 0; i < tag_len; ++i) {
        tag[i] = full_tag[i];
    }

    ascon_state_clean(&s);
    ascon_secure_zero(&k, sizeof(k));
    ascon_secure_zero(full_tag, sizeof(full_tag));
    return ASCON_SUCCESS;
}

static int aead_decrypt(uint8_t *plaintext,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t *tag, size_t tag_len,
                        const uint8_t *assoc_data, size_t assoc_data_len,
                        const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                        const uint8_t key[ASCON_AEAD128_KEY_LEN])
{
    ascon_state_t s;
    aead_key_t k;
    uint8_t expected_tag[ASCON_AEAD128_TAG_LEN];
    int diff;

    if (!aead_args_valid(plaintext, ciphertext, ciphertext_len,
                         assoc_data, assoc_data_len, tag, tag_len, nonce, key)) {
        return ASCON_INVALID_ARGUMENT;
    }

    k.k0 = ascon_load64_le(key);
    k.k1 = ascon_load64_le(key + 8);

    aead_initialize(&s, &k, nonce);
    aead_absorb_ad(&s, assoc_data, assoc_data_len);
    aead_decrypt_data(&s, plaintext, ciphertext, ciphertext_len);
    aead_finalize(&s, &k, expected_tag);

    /* Krok weryfikacji z Algorytmu 4: T' == T (dla tagu skroconego - na tag_len bajtach). */
    diff = constant_time_compare(expected_tag, tag, tag_len);

    ascon_state_clean(&s);
    ascon_secure_zero(&k, sizeof(k));
    ascon_secure_zero(expected_tag, sizeof(expected_tag));

    if (diff != 0) {
        /* Algorytm 4 zwraca "fail" - odszyfrowany tekst nie moze zostac uzyty. */
        if (ciphertext_len != 0) {
            ascon_secure_zero(plaintext, ciphertext_len);
        }
        return ASCON_TAG_MISMATCH;
    }
    return ASCON_SUCCESS;
}

/* API: Ascon-AEAD128 (Sekcja 4.1) */

int ascon_aead128_encrypt(uint8_t *ciphertext,
                          uint8_t tag[ASCON_AEAD128_TAG_LEN],
                          const uint8_t *plaintext,
                          size_t plaintext_len,
                          const uint8_t *assoc_data,
                          size_t assoc_data_len,
                          const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                          const uint8_t key[ASCON_AEAD128_KEY_LEN])
{
    return aead_encrypt(ciphertext, tag, ASCON_AEAD128_TAG_LEN,
                        plaintext, plaintext_len,
                        assoc_data, assoc_data_len, nonce, key);
}

int ascon_aead128_decrypt(uint8_t *plaintext,
                          const uint8_t *ciphertext,
                          size_t ciphertext_len,
                          const uint8_t tag[ASCON_AEAD128_TAG_LEN],
                          const uint8_t *assoc_data,
                          size_t assoc_data_len,
                          const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                          const uint8_t key[ASCON_AEAD128_KEY_LEN])
{
    return aead_decrypt(plaintext, ciphertext, ciphertext_len,
                        tag, ASCON_AEAD128_TAG_LEN,
                        assoc_data, assoc_data_len, nonce, key);
}

int ascon_verify_tag_constant_time(const uint8_t tag_a[ASCON_AEAD128_TAG_LEN],
                                   const uint8_t tag_b[ASCON_AEAD128_TAG_LEN])
{
    if (tag_a == NULL || tag_b == NULL) {
        return ASCON_INVALID_ARGUMENT;
    }
    return constant_time_compare(tag_a, tag_b, ASCON_AEAD128_TAG_LEN);
}

/* API: wariant ze skroconym tagiem (Sekcja 4.2.1) */

int ascon_aead128_encrypt_truncated(uint8_t *ciphertext,
                                    uint8_t *tag,
                                    size_t tag_len,
                                    const uint8_t *plaintext,
                                    size_t plaintext_len,
                                    const uint8_t *assoc_data,
                                    size_t assoc_data_len,
                                    const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                                    const uint8_t key[ASCON_AEAD128_KEY_LEN])
{
    return aead_encrypt(ciphertext, tag, tag_len,
                        plaintext, plaintext_len,
                        assoc_data, assoc_data_len, nonce, key);
}

int ascon_aead128_decrypt_truncated(uint8_t *plaintext,
                                    const uint8_t *ciphertext,
                                    size_t ciphertext_len,
                                    const uint8_t *tag,
                                    size_t tag_len,
                                    const uint8_t *assoc_data,
                                    size_t assoc_data_len,
                                    const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                                    const uint8_t key[ASCON_AEAD128_KEY_LEN])
{
    return aead_decrypt(plaintext, ciphertext, ciphertext_len,
                        tag, tag_len,
                        assoc_data, assoc_data_len, nonce, key);
}

/* API: wariant z maskowaniem nonce (Sekcja 4.2.2) */

/* N xor K2, gdzie K2 to druga polowa 256-bitowego klucza K = K1 || K2 (wzory 52-53). */
static void mask_nonce(uint8_t masked[ASCON_AEAD128_NONCE_LEN],
                       const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                       const uint8_t key[ASCON_AEAD128_NM_KEY_LEN])
{
    for (size_t i = 0; i < ASCON_AEAD128_NONCE_LEN; ++i) {
        masked[i] = (uint8_t)(nonce[i] ^ key[ASCON_AEAD128_KEY_LEN + i]);
    }
}

int ascon_aead128_nm_encrypt(uint8_t *ciphertext,
                             uint8_t tag[ASCON_AEAD128_TAG_LEN],
                             const uint8_t *plaintext,
                             size_t plaintext_len,
                             const uint8_t *assoc_data,
                             size_t assoc_data_len,
                             const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                             const uint8_t key[ASCON_AEAD128_NM_KEY_LEN])
{
    uint8_t masked_nonce[ASCON_AEAD128_NONCE_LEN];
    int ret;

    if (nonce == NULL || key == NULL) {
        return ASCON_INVALID_ARGUMENT;
    }

    /* Wzor (52): E(K1 || K2, N, A, P) = Ascon-AEAD128.enc(K1, N xor K2, A, P). */
    mask_nonce(masked_nonce, nonce, key);
    ret = aead_encrypt(ciphertext, tag, ASCON_AEAD128_TAG_LEN,
                       plaintext, plaintext_len,
                       assoc_data, assoc_data_len, masked_nonce, key);

    /* Wymaganie R2: zamaskowany nonce musi pozostac tajny. */
    ascon_secure_zero(masked_nonce, sizeof(masked_nonce));
    return ret;
}

int ascon_aead128_nm_decrypt(uint8_t *plaintext,
                             const uint8_t *ciphertext,
                             size_t ciphertext_len,
                             const uint8_t tag[ASCON_AEAD128_TAG_LEN],
                             const uint8_t *assoc_data,
                             size_t assoc_data_len,
                             const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                             const uint8_t key[ASCON_AEAD128_NM_KEY_LEN])
{
    uint8_t masked_nonce[ASCON_AEAD128_NONCE_LEN];
    int ret;

    if (nonce == NULL || key == NULL) {
        return ASCON_INVALID_ARGUMENT;
    }

    /* Wzor (53): D(K1 || K2, N, A, C, T) = Ascon-AEAD128.dec(K1, N xor K2, A, C, T). */
    mask_nonce(masked_nonce, nonce, key);
    ret = aead_decrypt(plaintext, ciphertext, ciphertext_len,
                       tag, ASCON_AEAD128_TAG_LEN,
                       assoc_data, assoc_data_len, masked_nonce, key);

    ascon_secure_zero(masked_nonce, sizeof(masked_nonce));
    return ret;
}
