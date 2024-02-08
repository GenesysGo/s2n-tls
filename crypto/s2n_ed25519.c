#include "crypto/s2n_ed25519.h"

#include <openssl/evp.h>

#include "crypto/s2n_ecc_evp.h"
#include "crypto/s2n_evp_signing.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_pkey.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_compiler.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_safety_macros.h"

static S2N_RESULT s2n_ed25519_signature_size(const struct s2n_pkey *pkey, uint32_t *size_out)
{
    RESULT_ENSURE_REF(size_out);
    *size_out = ED25519_SIG_SIZE;
    return S2N_RESULT_OK;
}

static int s2n_ed25519_sign(const struct s2n_pkey *priv, struct s2n_blob *message, struct s2n_blob *signature)
{
    POSIX_ENSURE_REF(priv);
    POSIX_ENSURE_REF(message);
    POSIX_ENSURE_REF(signature);
    POSIX_ENSURE(signature->size >= ED25519_SIG_SIZE, S2N_ERR_SIZE_MISMATCH);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv->key.ed25519_key.ed25519_key, NULL);
    POSIX_ENSURE_REF(ctx);

    size_t sig_len = signature->size;
    if (EVP_PKEY_sign_init(ctx) != 1 || EVP_PKEY_sign(ctx, signature->data, &sig_len, message->data, message->size) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return S2N_FAILURE;
    }

    signature->size = sig_len;
    EVP_PKEY_CTX_free(ctx);
    return S2N_SUCCESS;
}

static int s2n_ed25519_verify(const struct s2n_pkey *pub, struct s2n_blob *message, struct s2n_blob *signature)
{
    POSIX_ENSURE_REF(pub);
    POSIX_ENSURE_REF(message);
    POSIX_ENSURE_REF(signature);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub->key.ed25519_key.ed25519_key, NULL);
    POSIX_ENSURE_REF(ctx);

    if (EVP_PKEY_verify_init(ctx) != 1 || EVP_PKEY_verify(ctx, signature->data, signature->size, message->data, message->size) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return S2N_FAILURE;
    }

    EVP_PKEY_CTX_free(ctx);
    return S2N_SUCCESS;
}

static int s2n_ed25519_key_free(struct s2n_pkey *pkey)
{
    POSIX_ENSURE_REF(pkey);
    struct s2n_ed25519_key *ed25519_key = &pkey->key.ed25519_key;
    if (ed25519_key->ed25519_key != NULL) {
        EVP_PKEY_free(ed25519_key->ed25519_key);
        ed25519_key->ed25519_key = NULL;
    }
    return S2N_SUCCESS;
}

static int s2n_ed25519_check_key_exists(const struct s2n_pkey *pkey)
{
    const struct s2n_ed25519_key *ed25519_key = &pkey->key.ed25519_key;
    POSIX_ENSURE_REF(ed25519_key->ed25519_key);
    return 0;
}

S2N_RESULT s2n_evp_pkey_to_ed25519_private_key(s2n_ed25519_private_key *ed25519_key, EVP_PKEY *evp_private_key)
{
    RESULT_ENSURE(EVP_PKEY_base_id(evp_private_key) == EVP_PKEY_ED25519, S2N_ERR_KEY_MISMATCH);
    ed25519_key->ed25519_key = EVP_PKEY_dup(evp_private_key);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_evp_pkey_to_ed25519_public_key(s2n_ed25519_public_key *ed25519_key, EVP_PKEY *evp_public_key)
{
    RESULT_ENSURE(EVP_PKEY_base_id(evp_public_key) == EVP_PKEY_ED25519, S2N_ERR_KEY_MISMATCH);
    ed25519_key->ed25519_key = EVP_PKEY_dup(evp_public_key);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ed25519_pkey_init(struct s2n_pkey *pkey)
{
    pkey->sign = &s2n_ed25519_sign;
    pkey->size = &s2n_ed25519_signature_size;
    pkey->verify = &s2n_ed25519_verify;
    pkey->encrypt = NULL;  // Ed25519 does not support encryption
    pkey->decrypt = NULL;  // Ed25519 does not support decryption
    pkey->match = &s2n_ed25519_pkey_is_valid;
    pkey->free = &s2n_ed25519_key_free;
    pkey->check_key = &s2n_ed25519_check_key_exists;

    RESULT_GUARD(s2n_evp_signing_set_pkey_overrides(pkey));

    return S2N_RESULT_OK;
}

static int s2n_ed25519_pkey_is_valid(const struct s2n_pkey *pkey)
{
    POSIX_ENSURE_REF(pkey);
    struct s2n_ed25519_key *ed25519_key = &pkey->key.ed25519_key;
    POSIX_ENSURE_REF(ed25519_key->ed25519_key);

    // Check if the key type is EVP_PKEY_ED25519
    int key_type = EVP_PKEY_base_id(ed25519_key->ed25519_key);
    POSIX_ENSURE_EQ(key_type, EVP_PKEY_ED25519);

    return S2N_SUCCESS;
}