#include "XSalsa20Poly1305.h"
#include <sodium.h>
#include <glib.h>
#include <sys/time.h>
#include <stdio.h>
int decrypt_string_xs(const char *key, const char *str, char *dest, int len) {
    if (!key || !key[0])
        return 0;
    gsize out_len = 0;
    if (sodium_init() == -1) {
        return 0;
    }
    /*
       recommended password quality?

       pwgen -s 1048576|xz -9ve -|wc -c
       796718
       echo "45*8*796718/1048576"|bc
       result is 273 (Bits of entropy)

       so use pwgen -ns1 45 to get a good password

       because we just hash it down to crypto_secretbox_KEYBYTES
       using crypto_generichash (blake2b) without salt.
    */
    unsigned char hash[crypto_secretbox_KEYBYTES];
    crypto_generichash(hash, sizeof hash, (unsigned char*)key, sizeof key, NULL, 0);
    guchar * nonce_ciphertext;
    /* base64 decode the message */
    nonce_ciphertext = g_base64_decode(str, &out_len);
    int MESSAGE_LEN = out_len-(crypto_secretbox_NONCEBYTES+crypto_secretbox_MACBYTES);
    if (MESSAGE_LEN < 1) {
        g_free(nonce_ciphertext);
        return 0;
    }
    int CIPHERTEXT_LEN = crypto_secretbox_MACBYTES + MESSAGE_LEN;
    /* split it into nonce and ciphertext again */
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[CIPHERTEXT_LEN];
    memcpy(nonce, nonce_ciphertext, crypto_secretbox_NONCEBYTES);
    memcpy(ciphertext, nonce_ciphertext + crypto_secretbox_NONCEBYTES, CIPHERTEXT_LEN);
    g_free(nonce_ciphertext);
    /* decrypt the message */
    if (crypto_secretbox_open_easy((unsigned char*)dest, ciphertext, CIPHERTEXT_LEN, nonce, hash) != 0) {
        /* cannot decrypt */
        return 1;
    } else {
        /* successfully decrypted but... what's the timestamp? */
        unsigned long long millisecondsSinceEpochReceived = 0;
        /* get those 8 bytes out of the nonce */
        memcpy(&millisecondsSinceEpochReceived, nonce, sizeof millisecondsSinceEpochReceived);
        struct timeval tv;
        gettimeofday(&tv, NULL);
        /* we cast it to long long for year 2038 */
        unsigned long long millisecondsSinceEpoch =
            (unsigned long long)(tv.tv_sec) * 1000 +
            (unsigned long long)(tv.tv_usec) / 1000;
        /* messages that are more than 10000ms in the future are discarded */
        if (millisecondsSinceEpoch < millisecondsSinceEpochReceived) {
            if (millisecondsSinceEpochReceived-millisecondsSinceEpoch > 10000) {
                snprintf(dest, 34, "message too new (%013llums)", millisecondsSinceEpochReceived-millisecondsSinceEpoch);
                return 0;
            }
        } else {
            /* messages that are older than 10000ms are discarded */
            if (millisecondsSinceEpoch-millisecondsSinceEpochReceived > 10000) {
                snprintf(dest, 34, "message too old (%013llums)", millisecondsSinceEpoch-millisecondsSinceEpochReceived);
                return 0;
            }
        }

    }
    return 0;
}

int encrypt_string_xs(const char *key, const char *str, char *dest, int len) {
    if (!key || !key[0])
        return 0;
    if (sodium_init() == -1) {
        return 0;
    }
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[crypto_secretbox_MACBYTES+len];
    /* choosing a random nonce */
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    /* get 8 bytes of timestamp to mitigate risk of replay attacks */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    /* we cast it to long long for year 2038 */
    unsigned long long millisecondsSinceEpoch =
        (unsigned long long)(tv.tv_sec) * 1000 +
        (unsigned long long)(tv.tv_usec) / 1000;
    /* put those 8 bytes into the nonce keeping 16 random bytes */
    memcpy(nonce, &millisecondsSinceEpoch, sizeof millisecondsSinceEpoch);
    /* hash the password to get crypto_secretbox_KEYBYTES */
    unsigned char hash[crypto_secretbox_KEYBYTES];
    crypto_generichash(hash, sizeof hash, (unsigned char*)key, sizeof key, NULL, 0);
    /* encrypt the message */
    crypto_secretbox_easy(ciphertext, (const unsigned char*)str, len, nonce, hash);
    /* put nonce and ciphertext together */
    guchar nonce_ciphertext[crypto_secretbox_MACBYTES + len + crypto_secretbox_NONCEBYTES];
    memcpy(nonce_ciphertext, nonce, crypto_secretbox_NONCEBYTES);
    memcpy(nonce_ciphertext+crypto_secretbox_NONCEBYTES, ciphertext, crypto_secretbox_MACBYTES + len);
    /* and base64 encode it */
    gchar * encoded_str;
    encoded_str = g_base64_encode(nonce_ciphertext, crypto_secretbox_MACBYTES + len + crypto_secretbox_NONCEBYTES);
    strncpy(dest, encoded_str, ((crypto_secretbox_MACBYTES + len + crypto_secretbox_NONCEBYTES + 2) / 3 * 4) + 1);
    /* clean up a bit (maybe not needed) */
    sodium_memzero(nonce_ciphertext, crypto_secretbox_MACBYTES + len + crypto_secretbox_NONCEBYTES);
    sodium_memzero(ciphertext, crypto_secretbox_MACBYTES+len);
    sodium_memzero(nonce, crypto_secretbox_NONCEBYTES);
    /* sodium_memzero encoded_str? */
    g_free(encoded_str);
    return 1;
}

void encrypt_key_xs(const char *key, char *encryptedKey) {
}
