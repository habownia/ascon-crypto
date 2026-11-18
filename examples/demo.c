/**
 * @file demo.c
 * @brief Przyklad dzialania Ascon-AEAD128 i Ascon-Hash256.
 *
 * Uruchomienie: make demo  lub  make demo MSG="tekst"
 */

#include "ascon/ascon.h"

#include <stdio.h>
#include <string.h>

#define MAX_LEN 1024

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("  %-22s", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void print_result(int ret)
{
    if (ret == ASCON_SUCCESS) {
        printf("  %-22s%s\n", "Wynik:", "ASCON_SUCCESS - tag poprawny");
    } else {
        printf("  %-22s%s\n", "Wynik:", "ASCON_TAG_MISMATCH - wiadomosc odrzucona");
    }
}

int main(int argc, char *argv[])
{
    const char *msg = (argc > 1) ? argv[1] : "Ascon dziala na naszej implementacji!";
    const char *ad = "naglowek: id=7";
    size_t msg_len = strlen(msg);
    size_t ad_len = strlen(ad);

    uint8_t key[16], nonce[16], tag[16];
    uint8_t ct[MAX_LEN], pt[MAX_LEN];
    int ret;

    if (msg_len == 0 || msg_len > MAX_LEN) {
        printf("Wiadomosc musi miec od 1 do %d bajtow.\n", MAX_LEN);
        return 1;
    }

    /* stale wartosci tylko do pokazu - normalnie klucz losowy, a nonce sie nie powtarza */
    for (int i = 0; i < 16; ++i) {
        key[i] = (uint8_t)i;
        nonce[i] = (uint8_t)(0x10 + i);
    }

    printf("[1] Ascon-AEAD128: szyfrowanie\n");
    printf("  %-22s\"%s\"\n", "Wiadomosc:", msg);
    printf("  %-22s\"%s\"\n", "Dane skojarzone (AD):", ad);
    ascon_aead128_encrypt(ct, tag, (const uint8_t *)msg, msg_len, (const uint8_t *)ad, ad_len, nonce, key);
    print_hex("Szyfrogram:", ct, msg_len);
    print_hex("Tag:", tag, 16);

    printf("\n[2] Ascon-AEAD128: odszyfrowanie\n");
    ret = ascon_aead128_decrypt(pt, ct, msg_len, tag, (const uint8_t *)ad, ad_len, nonce, key);
    print_result(ret);
    printf("  %-22s\"%.*s\"\n", "Odzyskana wiadomosc:", (int)msg_len, (char *)pt);

    printf("\n[3] Atak: zmiana 1 bitu szyfrogramu\n");
    ct[0] ^= 0x01;
    ret = ascon_aead128_decrypt(pt, ct, msg_len, tag, (const uint8_t *)ad, ad_len, nonce, key);
    print_result(ret);
    ct[0] ^= 0x01;

    printf("\n[3] Atak: podmiana danych skojarzonych\n");
    ret = ascon_aead128_decrypt(pt, ct, msg_len, tag, (const uint8_t *)"naglowek: id=8", 14, nonce, key);
    print_result(ret);

    printf("\n[4] Ascon-Hash256\n");
    uint8_t h1[32], h2[32], msg2[MAX_LEN + 1];
    memcpy(msg2, msg, msg_len);
    msg2[msg_len] = '.';
    ascon_hash256(h1, (const uint8_t *)msg, msg_len);
    ascon_hash256(h2, msg2, msg_len + 1);
    print_hex("Hash(wiadomosc):", h1, 32);
    print_hex("Hash(wiadomosc+\".\"):", h2, 32);

    int diff = 0;
    for (int i = 0; i < 32; ++i) {
        for (uint8_t x = h1[i] ^ h2[i]; x; x >>= 1) {
            diff += x & 1;
        }
    }
    printf("  -> rozni sie %d z 256 bitow\n", diff);

    return 0;
}
