#include "ext.h"

/* Grows stage by stage (docs/EXT_ROADMAP.md, section 6.4). */
const char *const ext_features[] = {
    "ext", /* X0: the --ext switch */
#if GENEVA_EXT_CRYPTO
    "ext_crypto", /* X2: AES-GCM, HKDF; QUIC Initial decryption */
#endif
    0,
};
