/* Test-only OpenSSH FIDO provider. Never use its keys outside the disposable
 * lab: the handle deliberately contains the private key. OpenSSH's sk-api.h
 * is unchanged from openssh-portable V_9_2_P1 (its license is in that file).
 */
#include <stdint.h>
#include "sk-api.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint32_t sk_api_version(void) { return SSH_SK_VERSION_MAJOR; }
static int pin_required(uint8_t flags, const char *pin) {
    return (flags & SSH_SK_USER_VERIFICATION_REQD) &&
        (!pin || strcmp(pin, "fixture-unlock") != 0);
}
static int unavailable(void) {
    const char *path = getenv("SYQ_TEST_SK_UNAVAILABLE");
    return path && access(path, F_OK) == 0;
}

int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags, const char *pin,
    struct sk_option **options, struct sk_enroll_response **out) {
    (void)challenge; (void)challenge_len; (void)application; (void)options;
    if (unavailable()) return SSH_SK_ERR_DEVICE_NOT_FOUND;
    if (pin_required(flags, pin)) return SSH_SK_ERR_PIN_REQUIRED;
    struct sk_enroll_response *r = calloc(1, sizeof(*r));
    if (!r) return SSH_SK_ERR_GENERAL;
    r->flags = flags;
    EVP_PKEY *key = NULL;
    if (alg == SSH_SK_ED25519) {
        key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        r->public_key_len = 32;
        r->public_key = malloc(32);
        if (!key || !r->public_key || EVP_PKEY_get_raw_public_key(key, r->public_key, &r->public_key_len) != 1) goto fail;
    } else if (alg == SSH_SK_ECDSA) {
        key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
        EC_KEY *ec = key ? EVP_PKEY_get1_EC_KEY(key) : NULL;
        if (!ec) goto fail;
        const EC_GROUP *g = EC_KEY_get0_group(ec);
        const EC_POINT *q = EC_KEY_get0_public_key(ec);
        r->public_key_len = EC_POINT_point2buf(g, q, POINT_CONVERSION_UNCOMPRESSED, &r->public_key, NULL);
        EC_KEY_free(ec);
        if (!r->public_key_len) goto fail;
    } else goto fail;
    int length = i2d_PrivateKey(key, NULL);
    if (length <= 0) goto fail;
    r->key_handle = malloc((size_t)length);
    if (!r->key_handle) goto fail;
    unsigned char *cursor = r->key_handle;
    if (i2d_PrivateKey(key, &cursor) != length) goto fail;
    r->key_handle_len = (size_t)length;
    EVP_PKEY_free(key);
    *out = r;
    return 0;
fail:
    EVP_PKEY_free(key);
    free(r->public_key); free(r->key_handle); free(r);
    return SSH_SK_ERR_GENERAL;
}

int sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
    const char *application, const uint8_t *handle, size_t handle_len,
    uint8_t flags, const char *pin, struct sk_option **options,
    struct sk_sign_response **out) {
    (void)options;
    if (unavailable()) return SSH_SK_ERR_DEVICE_NOT_FOUND;
    if (pin_required(flags, pin)) return SSH_SK_ERR_PIN_REQUIRED;
    const unsigned char *cursor = handle;
    EVP_PKEY *key = d2i_AutoPrivateKey(NULL, &cursor, (long)handle_len);
    struct sk_sign_response *r = calloc(1, sizeof(*r));
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!key || !r || !ctx) goto fail;
    r->flags = flags;
    r->counter = 1;
    uint8_t message[69];
    SHA256((const unsigned char *)application, strlen(application), message);
    message[32] = flags;
    message[33] = message[34] = message[35] = 0;
    message[36] = 1;
    SHA256(data, data_len, message + 37);
    const EVP_MD *digest = alg == SSH_SK_ED25519 ? NULL : EVP_sha256();
    uint8_t signature[128];
    size_t length = sizeof(signature);
    if (EVP_DigestSignInit(ctx, NULL, digest, NULL, key) != 1 ||
        EVP_DigestSign(ctx, signature, &length, message, sizeof(message)) != 1) goto fail;
    if (alg == SSH_SK_ED25519) {
        r->sig_r = malloc(length);
        if (!r->sig_r) goto fail;
        memcpy(r->sig_r, signature, length);
        r->sig_r_len = length;
    } else {
        const unsigned char *p = signature;
        ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)length);
        if (!sig) goto fail;
        const BIGNUM *x, *y;
        ECDSA_SIG_get0(sig, &x, &y);
        r->sig_r_len = (size_t)BN_num_bytes(x);
        r->sig_s_len = (size_t)BN_num_bytes(y);
        r->sig_r = malloc(r->sig_r_len);
        r->sig_s = malloc(r->sig_s_len);
        if (!r->sig_r || !r->sig_s) { ECDSA_SIG_free(sig); goto fail; }
        BN_bn2bin(x, r->sig_r); BN_bn2bin(y, r->sig_s);
        ECDSA_SIG_free(sig);
    }
    EVP_PKEY_free(key); EVP_MD_CTX_free(ctx);
    *out = r;
    return 0;
fail:
    EVP_PKEY_free(key); EVP_MD_CTX_free(ctx);
    if (r) { free(r->sig_r); free(r->sig_s); free(r); }
    return SSH_SK_ERR_GENERAL;
}

int sk_load_resident_keys(const char *pin, struct sk_option **options,
    struct sk_resident_key ***rks, size_t *nrks) {
    (void)pin; (void)options; (void)rks; (void)nrks;
    return SSH_SK_ERR_UNSUPPORTED;
}
