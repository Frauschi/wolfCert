# SPDX-License-Identifier: GPL-3.0-or-later

if(WOLFCERT_ENABLE_EST)
    add_executable(example_enroll_est  enroll_est.c)
    target_link_libraries(example_enroll_est  PRIVATE wolfcert)

    if(_have_WOLF_CRYPTO_CB)
        add_executable(example_enroll_cryptocb enroll_cryptocb.c)
        target_link_libraries(example_enroll_cryptocb PRIVATE wolfcert)

        if(TARGET PkgConfig::WOLFSSL)
            set(_wc_example_wolfssl PkgConfig::WOLFSSL)
        else()
            set(_wc_example_wolfssl wolfssl::wolfssl)
        endif()

        find_package(wolftpm CONFIG QUIET)
        unset(_have_tpm_key_id CACHE)
        if(TARGET wolfssl::wolftpm)
            set(CMAKE_REQUIRED_LIBRARIES wolfssl::wolftpm ${_wc_example_wolfssl})
            check_c_source_compiles("${_wc_wolfssl_prologue}
                #include <wolftpm/tpm2_wrap.h>
                #if !defined(WOLFTPM_CRYPTOCB) || !defined(WOLF_PRIVATE_KEY_ID)
                #error missing
                #endif
                int main(void) { return 0; }
            " _have_tpm_key_id)
            unset(CMAKE_REQUIRED_LIBRARIES)
        endif()
        if(_have_tpm_key_id)
            add_executable(example_enroll_tpm enroll_tpm.c)
            target_link_libraries(example_enroll_tpm
                PRIVATE wolfcert wolfssl::wolftpm)
        else()
            message(STATUS "wolfCert: wolfTPM not found or without its "
                           "CryptoCb, skipping examples/enroll_tpm.c")
        endif()

        set(CMAKE_REQUIRED_LIBRARIES ${_wc_example_wolfssl})
        unset(_have_pkcs11_persist CACHE)
        check_c_source_compiles("${_wc_wolfssl_prologue}
            #if !defined(HAVE_PKCS11) || !defined(WOLF_PRIVATE_KEY_ID)
            #error missing
            #endif
            #include <wolfssl/wolfcrypt/wc_pkcs11.h>
            int main(void)
            {
                int (*persist)(Pkcs11Token*, int, void*) = wc_Pkcs11PersistKey;
                int (*del)(Pkcs11Token*, int, void*) = wc_Pkcs11DeleteKey;
                return persist == del;
            }
        " _have_pkcs11_persist)
        unset(CMAKE_REQUIRED_LIBRARIES)
        if(_have_pkcs11_persist)
            add_executable(example_enroll_pkcs11 enroll_pkcs11.c)
            target_link_libraries(example_enroll_pkcs11 PRIVATE wolfcert)
        else()
            message(STATUS "wolfCert: wolfSSL lacks PKCS#11 key ids or "
                           "wc_Pkcs11PersistKey, skipping "
                           "examples/enroll_pkcs11.c")
        endif()
    endif()
endif()

if(WOLFCERT_ENABLE_SCEP)
    add_executable(example_enroll_scep enroll_scep.c)
    target_link_libraries(example_enroll_scep PRIVATE wolfcert)
endif()
