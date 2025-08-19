// wolf sftp_client.c


#include <esp_log.h>


/* wolfSSL  */
/* always include wolfSSL user_settings.h first */
#include "user_settings.h" 

#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/version.h>

/* wolfSSH  */
#include <wolfssh/ssh.h>
//#include <wolfssh/internal.h>
#include <wolfssh/log.h>
// WolfSSL 사용자 설정을 가장 먼저 포함
//#include "user_settings.h"
//#include "sftp_client.h"
#include <wolfssh/wolfsftp.h>
#include <wolfssh/port.h>
//#include <wolfssl/wolfcrypt/ecc.h>
//#include <wolfssl/wolfcrypt/coding.h>
#include "common.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <errno.h>

// SFTP 서버 설정
#define SFTP_SERVER_IP "192.168.0.2"    // SFTP 서버 IP 주소
#define SFTP_SERVER_PORT 14022
#define SFTP_USERNAME "sftpuser2021"           // SFTP 사용자명
#define SFTP_PASSWORD "sftp@user2021"          // SFTP 비밀번호

#define SFTP_RESUME 0

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
void list_spiffs_files(const char *path);

bool is_eth_connected();

static const char *TAG = "sftp";

// 공개키 검증 콜백 (sftpclient.c 참조)
//static int sftp_public_key_check(byte* publicKey, word32 publicKeySz, void* ctx)
static int sftp_public_key_check(const unsigned char* publicKey, unsigned int publicKeySz, void* ctx)
{
    (void)publicKey;
    (void)publicKeySz; 
    (void)ctx;
    
    ESP_LOGI(TAG, "Public key check - accepting any key for now");
    return 0; // 모든 키 허용 (운영환경에서는 적절한 검증 필요)
}


// 사용자 인증 콜백
static int sftp_user_auth_callback(byte authType, WS_UserAuthData* authData, void* ctx) 
{
    const char* password = (const char*)ctx;
    int ret = WOLFSSH_USERAUTH_FAILURE;
    
    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        authData->sf.password.password = (byte*)password;
        authData->sf.password.passwordSz = strlen(password);
        ret = WOLFSSH_USERAUTH_SUCCESS;
    }
    
    return ret;
}

// 소켓 연결 함수
static int create_socket_connection(const char* host, int port) 
{
    int sock;
    struct sockaddr_in server_addr;
    struct hostent* host_entry;
    
    ESP_LOGI(TAG, "Resolving hostname: %s", host);
    
    host_entry = gethostbyname(host);
    if (!host_entry) {
        ESP_LOGE(TAG, "Failed to resolve hostname: %s", host);
        return -1;
    }
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket: %d", errno);
        return -1;
    }
    
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, host_entry->h_addr_list[0], host_entry->h_length);
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to connect to %s:%d, errno: %d", host, port, errno);
        close(sock);
        return -1;
    }
    
    ESP_LOGI(TAG, "Successfully connected to %s:%d", host, port);
    return sock;
}

// SFTP 연결 함수
    char* pubKeyName = NULL;
    char* certName = NULL;
    char* caCert   = NULL;
sftp_connection_t* sftp_connect(const char* host, int port, const char* username, const char* password) 
{
    const char* privKeyName = NULL;
    int userEcc = 0;
	void* heap=NULL;

    if (!host || !username || !password) {
        ESP_LOGE(TAG, "Invalid parameters for SFTP connection");
        return NULL;
    }
    
    ESP_LOGI(TAG, "Starting SFTP connection to %s:%d as %s", host, port, username);

    wolfSSH_Debugging_ON();  


    // WolfSSH 전역 초기화
    static bool wolfssl_initialized = false;
    if (!wolfssl_initialized) {
        if (wolfSSH_Init() != WS_SUCCESS) {
            ESP_LOGE(TAG, "Failed to initialize WolfSSH");
            return NULL;
        }
        wolfssl_initialized = true;
    }
#ifdef WOLFSSH_NO_RSA
    userEcc = 1;
    /* peerEcc = 1; */
#endif
    int ret = ClientSetPrivateKey(privKeyName, userEcc, heap, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "Error setting private key");
    }

#ifdef WOLFSSH_CERTS
    /* passed in certificate to use */
    if (certName) {
        ret = ClientUseCert(certName, heap);
    }
    else
#endif
    {
        ret = ClientUsePubKey(pubKeyName, 0, heap);
    }
    if (ret != 0) {
        ESP_LOGE(TAG,"Error setting public key");
    }
    
    sftp_connection_t* conn = calloc(1, sizeof(sftp_connection_t));
    if (!conn) {
        ESP_LOGE(TAG, "Failed to allocate memory for connection");
        return NULL;
    }
    
    // 연결 정보 저장
    strncpy(conn->host, host, sizeof(conn->host) - 1);
    conn->port = port;
    strncpy(conn->username, username, sizeof(conn->username) - 1);
    strncpy(conn->password, password, sizeof(conn->password) - 1);
    conn->socket_fd = -1;
    conn->connected = false;
    conn->sftp_active = false;
    
    // SSH 컨텍스트 생성
    conn->ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (!conn->ctx) {
        ESP_LOGE(TAG, "Failed to create SSH context");
        free(conn);
        return NULL;
    }
    
    // 인증 콜백 설정
    wolfSSH_SetUserAuth(conn->ctx, sftp_user_auth_callback);
    wolfSSH_CTX_SetPublicKeyCheck(conn->ctx, sftp_public_key_check);

    // 소켓 연결
    conn->socket_fd = create_socket_connection(host, port);
    if (conn->socket_fd < 0) {
        wolfSSH_CTX_free(conn->ctx);
        free(conn);
        return NULL;
    }
    
    // SSH 세션 생성
    conn->ssh = wolfSSH_new(conn->ctx);
    if (!conn->ssh) {
        ESP_LOGE(TAG, "Failed to create SSH session");
        close(conn->socket_fd);
        wolfSSH_CTX_free(conn->ctx);
        free(conn);
        return NULL;
    }

	//if (password != NULL)
	//wolfSSH_SetUserAuthCtx(conn->ssh, (void*)password);

    //wolfSSH_SetPublicKeyCheckCtx(conn->ssh, (void*)host);

    //int ret = wolfSSH_SetUsername(conn->ssh, username);
    //if (ret != WS_SUCCESS)
    //    ESP_LOGE(TAG,"Couldn't set the username.");  

    // 사용자 이름 설정
	//wolfSSH_SetUserAuth(conn->ssh, username);
    // 비밀번호 인증 콜백 설정
    //wolfSSH_SetUserAuthPassword(conn->ssh, password);


    wolfSSH_SetUsername(conn->ssh, username);
    wolfSSH_SetUserAuthCtx(conn->ssh, (void*)conn->password);
    wolfSSH_SetPublicKeyCheckCtx(conn->ssh, (void*)host);
    
    // 설정
    wolfSSH_set_fd(conn->ssh, conn->socket_fd);

    // SSH 연결 및 인증
    int result = wolfSSH_connect(conn->ssh);
    if (result != WS_SUCCESS) {
        ESP_LOGE(TAG, "Failed to authenticate with server (result: %d)", result);
        wolfSSH_free(conn->ssh);
        close(conn->socket_fd);
        wolfSSH_CTX_free(conn->ctx);
        free(conn);
        return NULL;
    }
    conn->connected = true;
 
    // SFTP 서브시스템 시작
    result = wolfSSH_SFTP_connect(conn->ssh);
    if (result != WS_SUCCESS) {
        ESP_LOGE(TAG, "Failed to start SFTP subsystem (result: %d)", result);
        wolfSSH_shutdown(conn->ssh);
        wolfSSH_free(conn->ssh);
        close(conn->socket_fd);
        wolfSSH_CTX_free(conn->ctx);
        free(conn);
        return NULL;
    }

    conn->sftp_active = true;
    ESP_LOGI(TAG, "✓ SFTP connection established successfully");
    return conn;
}

// SFTP 연결 해제
void sftp_disconnect(sftp_connection_t* conn) {
    if (!conn) return;
    
    ESP_LOGI(TAG, "Disconnecting SFTP connection...");
    
    if (conn->ssh && conn->connected) {
        wolfSSH_shutdown(conn->ssh);
        wolfSSH_free(conn->ssh);
    }
    
    if (conn->socket_fd >= 0) {
        close(conn->socket_fd);
    }
    
    if (conn->ctx) {
        wolfSSH_CTX_free(conn->ctx);
    }
    
    free(conn);
    ESP_LOGI(TAG, "SFTP connection closed successfully");
}


#if 0
// 파일 업로드 함수
int sftp_upload_file_streaming(sftp_connection_t* conn, const char* local_file, const char* remote_file) 
{
    if (!conn || !conn->connected || !conn->sftp_active || !local_file || !remote_file) {
        ESP_LOGE(TAG, "Invalid connection or parameters for upload");
        return -1;
    }
    
    ESP_LOGI(TAG, "Uploading file: %s -> %s", local_file, remote_file);
    
    // 로컬 파일 존재 확인
    FILE* test_file = fopen(local_file, "r");
    if (!test_file) {
        ESP_LOGE(TAG, "Local file does not exist: %s", local_file);
        return -1;
    }
    fclose(test_file);
    
    // wolfSSH의 PUT 함수 사용 (sftpclient.c와 동일)
    int result;
    int err;

    do {
        while (result == WS_REKEYING || conn->ssh->error == WS_REKEYING) {
            result = wolfSSH_worker(conn->ssh, NULL);
            if (result != WS_SUCCESS && result == WS_FATAL_ERROR) {
                result = wolfSSH_get_error(conn->ssh);
            }
        }

        result = wolfSSH_SFTP_Put(conn->ssh, (char*)local_file, (char*)remote_file, SFTP_RESUME, NULL);
        if (result != WS_SUCCESS && result == WS_FATAL_ERROR) {
            result = wolfSSH_get_error(conn->ssh);
        }
    } while (result == WS_WANT_READ || result == WS_WANT_WRITE ||
            result == WS_CHAN_RXD || result == WS_REKEYING);
    
    if (result == WS_SUCCESS) {
        ESP_LOGI(TAG, "✓ Upload completed successfully");
        return 0;
    } else {
        err = wolfSSH_get_error(conn->ssh);
        ESP_LOGE(TAG, "✗ Upload failed (result: %d, error: %d)", result, err);
        return -1;
    }
}

// 파일 다운로드 함수
int sftp_download_file_streaming(sftp_connection_t* conn, const char* remote_file, const char* local_file) {
    if (!conn || !conn->connected || !conn->sftp_active || !remote_file || !local_file) {
        ESP_LOGE(TAG, "Invalid connection or parameters for download");
        return -1;
    }
    
    ESP_LOGI(TAG, "Downloading file: %s -> %s", remote_file, local_file);
    
    // wolfSSH의 GET 함수 사용 (sftpclient.c와 동일)
    int result;
    int err;
    
    do {
        while (result == WS_REKEYING || conn->ssh->error == WS_REKEYING) {
            result = wolfSSH_worker(conn->ssh, NULL);
            if (result != WS_SUCCESS && result == WS_FATAL_ERROR) {
                result = wolfSSH_get_error(conn->ssh);
            }
        }

        result = wolfSSH_SFTP_Get(conn->ssh, (char*)remote_file, (char*)local_file, SFTP_RESUME, NULL);
        if (result != WS_SUCCESS && result == WS_FATAL_ERROR) {
            result = wolfSSH_get_error(conn->ssh);
        }
    } while (result == WS_WANT_READ || result == WS_WANT_WRITE ||
            result == WS_CHAN_RXD || result == WS_REKEYING);
    
    if (result == WS_SUCCESS) {
        ESP_LOGI(TAG, "✓ Download completed successfully");
        return 0;
    } else {
        err = wolfSSH_get_error(conn->ssh);
        ESP_LOGE(TAG, "✗ Download failed (result: %d, error: %d)", result, err);
        return -1;
    }
}
#endif

#if 0
#endif

#if 0
// 디렉토리 목록 조회 함수
int sftp_list_directory(sftp_connection_t* conn, const char* path) {
    if (!conn || !conn->connected || !conn->sftp_active) {
        ESP_LOGE(TAG, "Invalid connection for directory listing");
        return -1;
    }
    
    const char* target_path = path ? path : ".";
    WS_SFTPNAME* name_list = NULL;
    
    ESP_LOGI(TAG, "Listing directory: %s", target_path);
    
    name_list = wolfSSH_SFTP_LS(conn->ssh, (char*)target_path);
    if( name_list != NULL) {
        ESP_LOGI(TAG, "Directory listing for '%s':", target_path);
        
        WS_SFTPNAME* current = name_list;
        int file_count = 0;
        while (current) {
            ESP_LOGI(TAG, "  %s (size: %u bytes)", 
                     current->fName, 
                     (unsigned int)current->atrb.sz[1]);
            current = current->next;
            file_count++;
        }
        
        ESP_LOGI(TAG, "Total files/directories: %d", file_count);
        wolfSSH_SFTP_ClearName(name_list); 
        return 0;
    } else {
        ESP_LOGE(TAG, "Failed to list directory: %d", result);
        return -1;
    }
}

// 디렉토리 생성 함수
int sftp_mkdir(sftp_connection_t* conn, const char* path) {
    if (!conn || !conn->connected || !conn->sftp_active || !path) {
        ESP_LOGE(TAG, "Invalid connection or path for mkdir");
        return -1;
    }
    
    ESP_LOGI(TAG, "Creating directory: %s", path);
    
    int result = wolfSSH_SFTP_MKDIR(conn->ssh, (char*)path, NULL);
    if (result == WS_SUCCESS) {
        ESP_LOGI(TAG, "✓ Directory created successfully: %s", path);
        return 0;
    } else {
        ESP_LOGE(TAG, "Failed to create directory: %s (error: %d)", path, result);
        return -1;
    }
}

// 파일 삭제 함수
int sftp_remove_file(sftp_connection_t* conn, const char* remote_file) {
    if (!conn || !conn->connected || !conn->sftp_active || !remote_file) {
        ESP_LOGE(TAG, "Invalid connection or filename for remove");
        return -1;
    }
    
    ESP_LOGI(TAG, "Removing file: %s", remote_file);
    
    int result = wolfSSH_SFTP_Remove(conn->ssh, (char*)remote_file);
    if (result == WS_SUCCESS) {
        ESP_LOGI(TAG, "✓ File removed successfully: %s", remote_file);
        return 0;
    } else {
        ESP_LOGE(TAG, "Failed to remove file: %s (error: %d)", remote_file, result);
        return -1;
    }
}

// 파일 존재 확인 함수
int sftp_file_exists(sftp_connection_t* conn, const char* remote_file) {
    if (!conn || !conn->connected || !conn->sftp_active || !remote_file) {
        ESP_LOGW(TAG, "Invalid parameters for file existence check");
        return 0; // 존재하지 않는 것으로 간주
    }
    
    ESP_LOGI(TAG, "Checking if file exists: %s", remote_file);
    
    WS_SFTP_FILEATRB* atrb = wolfSSH_SFTP_STAT(conn->ssh, remote_file);
    if (atrb) {
        ESP_LOGI(TAG, "✓ File exists: %s (size: %u bytes)", 
                 remote_file, (unsigned int)atrb->sz[1]);
        free(atrb);
        return 1; // 파일 존재
    } else {
        ESP_LOGI(TAG, "File does not exist: %s", remote_file);
        return 0; // 파일 없음
    }
}
#endif




static void sftp_client_task(void *pvParameters)
{
    sftp_connection_t* conn;

    ESP_LOGI(TAG, "Starting improved SFTP client...");
#if 0   
    //--- 단일 파일 업로드 테스트 ----------------------------------------------------------------------
    if( (conn= sftp_connect( SFTP_SERVER_IP, SFTP_SERVER_PORT, SFTP_USERNAME, SFTP_PASSWORD ))==NULL ) {
        ESP_LOGE(TAG, "Failed to establish SFTP connection");
        vTaskDelete(NULL);
        return;
    }

    //if( sftp_upload_file_streaming(conn, "/spiffs/upload.txt", "esp32_upload.txt")==0 ) {
    //    ESP_LOGI(TAG, "✓ Single file upload successful");
    //}
    sftp_disconnect(conn);     // 연결 종료
#endif
    vTaskDelay(pdMS_TO_TICKS(5000));    // wait 5 sec
#if 0
    //--- 단일 파일 다운로드 테스트 -------------------------------------------------------------------
    if( (conn= sftp_connect( SFTP_SERVER_IP, SFTP_SERVER_PORT, SFTP_USERNAME, SFTP_PASSWORD ))==NULL ) {
        ESP_LOGE(TAG, "Failed to establish SFTP connection");
        vTaskDelete(NULL);
        return;
    }

    if (sftp_download_file_streaming(conn, "esp32_upload.txt", "/spiffs/downloaded.txt") == 0) {
        ESP_LOGI(TAG, "✓ File download successful");
    }
    sftp_disconnect(conn);     // 연결 종료
#endif
    list_spiffs_files("/spiffs");
    
    vTaskDelete(NULL);
}


void init_sftp_client_task(void)
{
    // 이더넷 연결 대기
    ESP_LOGI(TAG, "Waiting for ethernet connection...");
//  xEventGroupWaitBits(s_eth_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
    while (!is_eth_connected()) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    ESP_LOGI(TAG, "Ethernet connected, starting SFTP operations");


//    WOLFSSH_CTX* ctx= wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);;
//    WOLFSSH* ssh= wolfSSH_new(ctx);;
    // SFTP 클라이언트 태스크 생성
    //xTaskCreate(sftp_client_task, "sftp_client_task", 8192, NULL, 5, NULL);
    ESP_LOGI(TAG, "Test 1: Upload file");
    if (esp32_sftp_upload("/spiffs/upload.txt", "esp32_test.txt") == 0) {
        ESP_LOGI(TAG, "✓ Upload test successful");
    } else {
        ESP_LOGE(TAG, "✗ Upload test failed");
    }
}