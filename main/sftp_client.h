// main/sftp_client.h
#ifndef SFTP_CLIENT_H
#define SFTP_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
//#include "esp_vfs.h"
#include "esp_spiffs.h"

// WolfSSL 사용자 설정을 먼저 포함
#include "user_settings.h"

// WolfSSH includes - 사용자 설정 이후에 포함
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssh/ssh.h"
#include "wolfssh/wolfscp.h"
#include "wolfssh/wolfsftp.h"

#define SFTP_CLIENT_TAG "SFTP_CLIENT"
#define SFTP_BUFFER_SIZE 4096
#define DEFAULT_TIMEOUT_MS 30000

// SFTP 연결 구조체
typedef struct {
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int socket_fd;
    char host[64];
    int port;
    char username[32];
    char password[64];
    bool connected;
    bool sftp_active;
} sftp_connection_t;

// 간단한 API 함수들
sftp_connection_t* sftp_connect(const char* host, int port, const char* username, const char* password);
void sftp_disconnect(sftp_connection_t* conn);

// 스트리밍 파일 전송 함수들
int sftp_upload_file_streaming(sftp_connection_t* conn, const char* local_file, const char* remote_file);
int sftp_download_file_streaming(sftp_connection_t* conn, const char* remote_file, const char* local_file);

// 추가 유틸리티 함수들
int sftp_list_directory(sftp_connection_t* conn, const char* path);
int sftp_mkdir(sftp_connection_t* conn, const char* path);
int sftp_remove_file(sftp_connection_t* conn, const char* remote_file);
int sftp_file_exists(sftp_connection_t* conn, const char* remote_file);

#endif // SFTP_CLIENT_H