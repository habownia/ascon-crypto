/**
 * @file ascon_hash.c
 * @brief Implementacja Ascon-Hash256 (Algorithm 5), NIST SP 800-232.
 *
 *
 * Budowa (konstrukcja gąbkowa, Figure 7):
 *  - stan 320 bitow = czesc "rate" (S0, 64 bity) + czesc "capacity" (S1..S4, 256 bitow),
 *  - wiadomosc jest wchlaniana (absorbing) blokami po 8 bajtow do S0,
 *    a po kazdym bloku wykonywana jest permutacja p[12],
 *  - wynik jest wyciskany (squeezing) z S0 blokami po 8 bajtow, przedzielonymi p[12].
 *
 *
 * Uwagi:
 *  - Bajty wiadomosci laduja sie do S0 w porzadku little-endian (Dodatek A.2),
 *    padding 10* to ascon_pad(len) = 0x01 << (8 * len) (Table 11).
 *  - Funkcje nie kopiuja wiadomosci ani nie alokuja pamieci - zuzywaja tylko
 *    stan (40 B) na stosie, co jest istotne na ESP8266/ESP32.
 *  - Na koniec stan jest bezpiecznie zerowany.
 *  - API przyjmuje dlugosci w bajtach; standard podaje L w bitach (L = 8 * out_len).
 */

#include "ascon/ascon_hash.h"
#include "ascon/ascon_permutation.h"

/* Fazy algorytmu (wspolne dla Hash256) */

/**
 * Inicjalizacja: S = p[12](IV || 0^256).
 * Hash256: wzory (54)-(55). XOF128: wzory (66)-(67).
 *
 * Wynik jest staly (Table 12, Dodatek A.3), wiec mozna by go wpisac jako stala
 * i zaoszczedzic jedno p[12]. Liczymy go jednak jawnie - kod odpowiada wtedy
 * wprost standardowi, a test permutacji (Table 12) i tak pilnuje poprawnosci.
 */
static void sponge_initialize(ascon_state_t *s, uint64_t iv)
{
    ascon_state_init(s);
    s->x[0] = iv;
    ascon_p12(s);
}

/**
 * Wchlanianie wiadomosci. Hash256: wzory (56)-(61). XOF128: wzory (68)-(73).
 *
 * M jest dzielona na bloki 64-bitowe M_0..M_{n-1}, przy czym ostatni blok jest
 * dopelniany paddingiem 10* (zawsze - takze gdy dlugosc M jest wielokrotnoscia
 * 8 bajtow; wtedy ostatni blok to sam padding 0x01).
 * Dla kazdego pelnego bloku: S0 = S0 xor M_i, S = p[12](S).
 * Ostatni (dopelniony) blok jest tylko XOR-owany - permutacja, ktora po nim
 * nastepuje, to pierwszy krok fazy wyciskania (tak zapisuja to Algorytmy 5 i 6).
 */
static void sponge_absorb(ascon_state_t *s, const uint8_t *data, size_t data_len)
{
    /* Pelne bloki 8-bajtowe. */
    while (data_len >= ASCON_XOF128_RATE) {
        s->x[0] ^= ascon_load64_le(data);
        ascon_p12(s);
        data += ASCON_XOF128_RATE;
        data_len -= ASCON_XOF128_RATE;
    }

    /* Ostatni blok: 0..7 pozostalych bajtow + padding. */
    s->x[0] ^= ascon_load_bytes_le(data, data_len);
    s->x[0] ^= ascon_pad(data_len);
}

/**
 * Wyciskanie out_len bajtow. Hash256: wzory (62)-(65). XOF128: wzory (74)-(78).
 *
 * S = p[12](S); potem H_i = S0 i S = p[12](S) dla kolejnych blokow,
 * a po ostatnim bloku permutacji juz sie nie wykonuje. Ostatni blok moze byc
 * niepelny (XOF128 z out_len niepodzielnym przez 8) - wtedy zapisujemy tylko
 * potrzebne bajty, co odpowiada obcieciu H' do L bitow (H = H'[0:L-1]).
 */
static void sponge_squeeze(ascon_state_t *s, uint8_t *out, size_t out_len)
{
    ascon_p12(s);
    while (out_len > ASCON_XOF128_RATE) {
        ascon_store64_le(out, s->x[0]);
        ascon_p12(s);
        out += ASCON_XOF128_RATE;
        out_len -= ASCON_XOF128_RATE;
    }
    ascon_store_bytes_le(out, s->x[0], out_len);
}

/* API                                                                       */

int ascon_hash256(uint8_t digest[ASCON_HASH256_DIGEST_LEN],
                  const uint8_t *data,
                  size_t data_len)
{
    ascon_state_t s;

    if (digest == NULL || (data == NULL && data_len != 0)) {
        return -1;
    }

    sponge_initialize(&s, ASCON_HASH256_IV);
    sponge_absorb(&s, data, data_len);
    sponge_squeeze(&s, digest, ASCON_HASH256_DIGEST_LEN);

    ascon_state_clean(&s);
    return 0;
}
