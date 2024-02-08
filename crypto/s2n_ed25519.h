

#pragma once

#include <openssl/evp.h>
#include <stdint.h>

#include "api/s2n.h"
#include "crypto/s2n_ecc_evp.h"
#include "crypto/s2n_hash.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_blob.h"

#define ED25519_SIG_SIZE 64

/* Forward declaration to avoid circular dependency with s2n_pkey.h */
struct s2n_pkey;

struct s2n_ed25519_key {
    /*
     * AWS-LC provides an EVP interface for Ed25519. We store a pointer to the EVP_PKEY
     * structure to manage the Ed25519 key. This allows us to use AWS-LC's EVP API for
     * key operations, signing, and verification.
     */
    EVP_PKEY *ed25519_key;
};

typedef struct s2n_ed25519_key s2n_ed25519_public_key;
typedef struct s2n_ed25519_key s2n_ed25519_private_key;

S2N_RESULT s2n_ed25519_pkey_init(struct s2n_pkey *pkey);
S2N_RESULT s2n_evp_pkey_to_ed25519_public_key(s2n_ed25519_public_key *ed25519_key, EVP_PKEY *pkey);
S2N_RESULT s2n_evp_pkey_to_ed25519_private_key(s2n_ed25519_private_key *ed25519_key, EVP_PKEY *pkey);