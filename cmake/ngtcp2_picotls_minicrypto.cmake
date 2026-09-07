# ngtcp2's picotls crypto backend, retargeted from picotls's OpenSSL binding to
# its minicrypto one.
#
# Upstream hardcodes ptls_openssl_* for the fixed Initial-packet suite and the
# header-protection lookups (crypto/picotls/picotls.c), so the shipped backend
# drags libcrypto in — the one thing this migration removes. The coupling is
# only in the names: the file itself talks to picotls through the generic
# ptls_aead_algorithm_t / ptls_hash_algorithm_t / ptls_cipher_algorithm_t
# abstractions and makes no direct OpenSSL call, and minicrypto declares every
# algorithm it asks for.
#
# The substitution is applied at configure time rather than as a patch on the
# fetched tree, so bumping ngtcp2 re-derives it instead of rejecting a stale
# patch, and the divergence stays one readable transformation.

set(_backend_source "${ngtcp2_SOURCE_DIR}/crypto/picotls/picotls.c")
set(_backend_generated "${CMAKE_BINARY_DIR}/ngtcp2-picotls-minicrypto/picotls.c")

file(READ "${_backend_source}" _backend_text)
string(REPLACE "#include <picotls/openssl.h>" "#include <picotls/minicrypto.h>" _backend_text "${_backend_text}")
string(REPLACE "ptls_openssl_" "ptls_minicrypto_" _backend_text "${_backend_text}")
# The rename above is case-sensitive and does not reach the feature macro, which
# gates every CHACHA20 branch. Left alone it silently compiles them out and the
# header-protection lookup returns NULL for a CHACHA20 suite.
string(FIND "${_backend_text}" "PTLS_OPENSSL_HAVE_CHACHA20_POLY1305" _chacha_macro_found)
if(_chacha_macro_found EQUAL -1)
    message(FATAL_ERROR "ngtcp2 picotls backend changed shape: the CHACHA20 feature macro is gone, re-derive it")
endif()
string(REPLACE "PTLS_OPENSSL_HAVE_CHACHA20_POLY1305" "PTLS_MINICRYPTO_CHACHA20_POLY1305" _backend_text "${_backend_text}")

# The one difference that is not a rename. Upstream calls ptls_cipher_init
# unconditionally on the ECB header-protection cipher, which is safe only
# because picotls's OpenSSL binding installs a do_init for it; minicrypto sets
# do_init to NULL (aes-common.h: ECB takes no IV), so the call dereferences
# NULL during Initial key derivation. Guard on the callback instead.
set(_ecb_init_original "  if (cipher->native_handle == &ptls_minicrypto_aes128ecb ||\n      cipher->native_handle == &ptls_minicrypto_aes256ecb) {\n    ptls_cipher_init(actx, NULL)")
set(_ecb_init_guarded "  if ((cipher->native_handle == &ptls_minicrypto_aes128ecb ||\n       cipher->native_handle == &ptls_minicrypto_aes256ecb) &&\n      actx->do_init != NULL) {\n    ptls_cipher_init(actx, NULL)")
string(FIND "${_backend_text}" "${_ecb_init_original}" _ecb_init_found)
if(_ecb_init_found EQUAL -1)
    message(FATAL_ERROR "ngtcp2 picotls backend changed shape: the ECB cipher-init guard no longer applies, re-derive it")
endif()
string(REPLACE "${_ecb_init_original}" "${_ecb_init_guarded}" _backend_text "${_backend_text}")

# The negotiated CHACHA20 suite uses our Monocypher-backed AEAD, so the backend
# has to recognise it: the identity comparisons are what select the header
# protection cipher and, just as importantly, the AEAD usage limits. Falling
# through would return a NULL header-protection cipher and lose the CHACHA20
# confidentiality bound. The CHACHA20 cipher itself stays minicrypto's, which
# is why only the longer AEAD symbol is substituted.
string(FIND "${_backend_text}" "&ptls_minicrypto_chacha20poly1305" _aead_found)
if(_aead_found EQUAL -1)
    message(FATAL_ERROR "ngtcp2 picotls backend changed shape: the CHACHA20-POLY1305 AEAD symbol is gone, re-derive it")
endif()
string(REPLACE "&ptls_minicrypto_chacha20poly1305" "&can_hub_chacha20poly1305" _backend_text "${_backend_text}")
string(REPLACE "#include <picotls/minicrypto.h>"
               "#include <picotls/minicrypto.h>\n#include \"platform/linux/shared/tls_aead.h\""
               _backend_text "${_backend_text}")

file(WRITE "${_backend_generated}" "${_backend_text}")

add_library(ngtcp2_crypto_picotls_minicrypto STATIC
    "${_backend_generated}"
    "${ngtcp2_SOURCE_DIR}/crypto/shared.c"
)
target_compile_definitions(ngtcp2_crypto_picotls_minicrypto
    PRIVATE BUILDING_NGTCP2 PTLS_MINICRYPTO_CHACHA20_POLY1305
    PUBLIC NGTCP2_STATICLIB
)
target_include_directories(ngtcp2_crypto_picotls_minicrypto PUBLIC
    "${ngtcp2_SOURCE_DIR}/lib/includes"
    "${ngtcp2_BINARY_DIR}/lib/includes"
    "${ngtcp2_SOURCE_DIR}/lib"
    "${ngtcp2_SOURCE_DIR}/crypto/includes"
    "${ngtcp2_SOURCE_DIR}/crypto"
    "${CAN_HUB_ROOT_DIR}/src"
)
target_link_libraries(ngtcp2_crypto_picotls_minicrypto PUBLIC picotls)
