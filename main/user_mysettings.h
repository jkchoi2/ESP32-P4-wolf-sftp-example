// main/user_settings.h
#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ESP-IDF 플랫폼 설정 */
#define WOLFSSL_ESP32
#define WOLFSSL_ESPWROOM32

/* 기본 암호화 알고리즘 */
#define NO_OLD_TLS
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_ECC
#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define HAVE_HKDF
#define WC_RSA_PSS

/* SSH/SFTP 지원 */
#define WOLFSSH_SFTP
#define WOLFSSH_SCP

/* 메모리 및 성능 최적화 */
#define WOLFSSL_SMALL_STACK
#define MAX_WOLFSSL_FILE_SIZE 1024*1024*10  // 10MB max file size

/* 디버그 설정 */
#ifdef DEBUG_WOLFSSL
    #define DEBUG_WOLFSSL_VERBOSE
#endif

/* ESP32 하드웨어 가속 */
//#define WOLFSSL_ESP32_CRYPT
//#define NO_ESP32_CRYPT_HASH
//#define NO_ESP32_CRYPT_HASH_SHA384
//#define NO_ESP32_CRYPT_HASH_SHA512

/* 사용하지 않는 기능들 비활성화 */
#define NO_DSA
#define NO_DH
#define NO_MD4
#define NO_RABBIT
#define NO_HC128
#define NO_RC4
#define WOLFSSL_NO_TLS12

/* RTOS 관련 설정 */
#define SINGLE_THREADED
#define WOLFSSL_LWIP

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */