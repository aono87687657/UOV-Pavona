// Re-sign a 3-line vector file (pk, sk seed, message||signature; hex) with a UOV reference implementation.
// randombytes() returns the salt of the recorded signature (its last 16 bytes) and must be called exactly once.
// Per case: crypto_sign must give the recorded signed message byte for byte, crypto_sign_open must accept it and
// reject it with one signature byte flipped, and the signer's Gaussian elimination (GE, linked with -Wl,--wrap=GE,
// one call per attempt) must fail on every call but the last. ATTEMPTS lists the expected attempts, one per case.
// Usage: refcheck FILE ATTEMPTS   (e.g. 1,2,3; exit 0 only if every case passes and the counts match)
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "utils_randombytes.h"

static unsigned char salt[_SALT_BYTE];
static int calls;

static void give_salt(unsigned char *x, unsigned long long xlen) {
    calls++;
    if (xlen != _SALT_BYTE) {
        fprintf(stderr, "randombytes(%llu): only the 16-byte salt is expected\n", xlen);
        exit(3);
    }
    memcpy(x, salt, xlen);
}

#ifdef PQM4   // the pqm4 (Round-2) build: size_t lengths, PQClean randombytes
typedef size_t len_t;
int randombytes(uint8_t *x, size_t xlen) {
    give_salt(x, xlen);
    return 0;
}
#else
typedef unsigned long long len_t;
void randombytes(unsigned char *x, unsigned long long xlen) {
    give_salt(x, xlen);
}
#endif

#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)
unsigned CAT(__real_, GE)(uint8_t *a, uint8_t *c, unsigned len);
static int ge_calls;
static char ge_trace[256];

unsigned CAT(__wrap_, GE)(uint8_t *a, uint8_t *c, unsigned len) {
    unsigned r = CAT(__real_, GE)(a, c, len);
    if (ge_calls < 255) {
        ge_trace[ge_calls] = r ? '1' : '0';
    }
    ge_calls++;
    return r;
}

static int nibble(char c) {
    return isdigit((unsigned char)c) ? c - '0' : tolower((unsigned char)c) - 'a' + 10;
}

// One line of hex digits (a trailing CR/LF allowed); NULL if anything else is in it.
static unsigned char *unhex(const char *s, size_t *n) {
    size_t len = strcspn(s, "\r\n");
    if (len % 2 || strspn(s, "0123456789abcdefABCDEF") != len) {
        return NULL;
    }
    unsigned char *b = malloc(len / 2 + 1);
    for (size_t i = 0; i < len / 2; i++) {
        b[i] = (unsigned char)(nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]));
    }
    *n = len / 2;
    return b;
}

// The next expected attempt count of a comma list: a positive decimal; -1 if the list is used up or malformed.
static int next_attempts(const char **list) {
    const char *s = *list;
    if (!*s || !isdigit((unsigned char)*s)) {
        return -1;
    }
    char *end;
    long v = strtol(s, &end, 10);
    if (v < 1 || v > 255 || (*end != ',' && *end != '\0') || (*end == ',' && !end[1])) {
        return -1;
    }
    *list = *end == ',' ? end + 1 : end;
    return (int)v;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s FILE ATTEMPTS\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror(argv[1]);
        return 2;
    }
    printf("%s: pk %d B, sk %d B, signature %d B\n", OV_ALGNAME, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, CRYPTO_BYTES);
    const char *want = argv[2];
    char *line[3] = {0};
    size_t cap[3] = {0};
    int bad = 0, n = 0;
    while (getline(&line[0], &cap[0], f) > 0) {
        int expected = next_attempts(&want);
        if (getline(&line[1], &cap[1], f) <= 0 || getline(&line[2], &cap[2], f) <= 0) {
            printf("case %d: incomplete record at the end of the file\n", n);
            bad++;
            n++;
            break;
        }
        size_t pkn = 0, skn = 0, smn = 0;
        unsigned char *pk = unhex(line[0], &pkn), *sk = unhex(line[1], &skn), *sm = unhex(line[2], &smn);
        int ok = pk && sk && sm && pkn == CRYPTO_PUBLICKEYBYTES && skn == CRYPTO_SECRETKEYBYTES && smn >= CRYPTO_BYTES;
        if (!ok || expected < 0) {
            printf("case %d: %s\n", n, ok ? "no valid expected attempt count left in ATTEMPTS" : "not hex or sizes wrong");
            free(pk); free(sk); free(sm);
            bad++;
            n++;
            continue;
        }
        len_t mlen = smn - CRYPTO_BYTES, outlen = 0, m2len = 0;
        memcpy(salt, sm + smn - _SALT_BYTE, _SALT_BYTE);
        unsigned char *out = malloc(smn + CRYPTO_BYTES), *m2 = malloc(smn), *flip = malloc(smn);
        calls = ge_calls = 0;
        memset(ge_trace, 0, sizeof ge_trace);
        int rs = crypto_sign(out, &outlen, sm, mlen, sk);
        int same = rs == 0 && calls == 1 && outlen == smn && memcmp(out, sm, smn) == 0;
        int tries = ge_calls, shape = tries >= 1 && tries < 255 && ge_trace[tries - 1] == '1' &&
                                       strspn(ge_trace, "0") == (size_t)(tries - 1);
        int ro = crypto_sign_open(m2, &m2len, sm, smn, pk);
        int opened = ro == 0 && m2len == mlen && memcmp(m2, sm, mlen) == 0;
        memcpy(flip, sm, smn);
        flip[mlen + n % (CRYPTO_BYTES - _SALT_BYTE)] ^= 1;
        int rejected = crypto_sign_open(m2, &m2len, flip, smn, pk) != 0;
        printf("case %d: %llu B message, sign %s (rc %d, randombytes calls %d), attempts %d (eliminations %s)%s, "
               "open %s, flipped %s\n", n, (unsigned long long)mlen, same ? "MATCH" : "DIFFERS", rs, calls, tries,
               ge_trace, tries == expected ? "" : " EXPECTED OTHER", opened ? "OK" : "FAILED",
               rejected ? "rejected" : "ACCEPTED");
        bad += !(same && opened && rejected && shape && tries == expected);
        n++;
        free(pk); free(sk); free(sm); free(out); free(m2); free(flip);
    }
    if (ferror(f)) {
        printf("read error in %s\n", argv[1]);
        bad++;
    }
    if (*want) {
        printf("more ATTEMPTS than cases\n");
        bad++;
    }
    printf("%d cases, %d failed\n", n, bad);
    return bad || !n;
}
