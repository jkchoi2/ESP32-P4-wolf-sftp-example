/* wifi_connect.h
 *
 * Copyright (C) 2014-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _WIFI_CONNECT_H_
#define _WIFI_CONNECT_H_

#include <esp_idf_version.h>
#include <esp_log.h>

/* ESP lwip */
#define EXAMPLE_ESP_MAXIMUM_RETRY       CONFIG_ESP_MAXIMUM_RETRY

#define TLS_SMP_SERVER_TASK_NAME         "tls_sever_example"
#define TLS_SMP_SERVER_TASK_WORDS        22240
#define TLS_SMP_SERVER_TASK_PRIORITY     8

#define TLS_SMP_WIFI_SSID                CONFIG_WIFI_SSID
#define TLS_SMP_WIFI_PASS                CONFIG_WIFI_PASSWORD

#define USE_WIFI_EXAMPLE
#ifdef USE_WIFI_EXAMPLE
    #include <protocol_examples_common.h> /* see project CMakeLists.txt */
#endif

/**
 ******************************************************************************
 ******************************************************************************
 ** USER APPLICATION SETTINGS BEGIN
 ******************************************************************************
 ******************************************************************************
 **/

/* when using a private config with plain text passwords,
 * file my_private_config.h should be excluded from git updates */
/* #define  USE_MY_PRIVATE_CONFIG */

#ifdef  USE_MY_PRIVATE_CONFIG
    #if defined(WOLFSSL_CMAKE_SYSTEM_NAME_WINDOWS)
        #include "/workspace/my_private_config.h"
    #elif defined(WOLFSSL_CMAKE_SYSTEM_NAME_WSL)
        #include "/mnt/c/workspace/my_private_config.h"
    #elif defined(WOLFSSL_CMAKE_SYSTEM_NAME_LINUX)
        #include "~/workspace/my_private_config.h"
    #elif defined(WOLFSSL_CMAKE_SYSTEM_NAME_APPLE)
        #include "~/Documents/my_private_config.h"
    #else
        #warning "did not detect environment. using ~/my_private_config.h"
        #include "~/my_private_config.h"
    #endif
#else

    /*
    ** The examples use WiFi configuration that you can set via project
    ** configuration menu
    **
    ** If you'd rather not, just change the below entries to strings with
    ** the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
    */
    /* Some older versions use ESP_WIFI_SSID via Kconfig */
    #ifdef CONFIG_ESP_WIFI_SSID
        /* Overwrite the example SSID with the value set in menuconfig */
        #undef  EXAMPLE_ESP_WIFI_SSID
        #define EXAMPLE_ESP_WIFI_SSID CONFIG_ESP_WIFI_SSID
    #endif

    /* Newer versions of the ESP-IDF use EXAMPLE_WIFI_SSID via Kconfig */
    #ifdef CONFIG_EXAMPLE_WIFI_SSID
        /* Overwrite the example SSID with the value set in menuconfig */
        #undef  EXAMPLE_ESP_WIFI_SSID
        #define EXAMPLE_ESP_WIFI_SSID CONFIG_EXAMPLE_WIFI_SSID
    #endif

    /* Some older versions use ESP_WIFI_PASSWORD via Kconfig */
    #ifdef CONFIG_ESP_WIFI_PASSWORD
        /* Overwrite the example password with the value set in menuconfig */
        #undef  EXAMPLE_ESP_WIFI_PASS
        #define EXAMPLE_ESP_WIFI_PASS CONFIG_ESP_WIFI_PASSWORD
    #endif

    /* Newer versions use CONFIG_ESP_WIFI_PASSWORD via Kconfig */
    #ifdef CONFIG_EXAMPLE_WIFI_PASSWORD
        /* Overwrite the example SSID with the value set in menuconfig */
        #undef  EXAMPLE_ESP_WIFI_PASS
        #define EXAMPLE_ESP_WIFI_PASS CONFIG_EXAMPLE_WIFI_PASSWORD
    #endif

#endif

 /* Ensure EXAMPLE_ESP_WIFI_SSID and EXAMPLE_ESP_WIFI_PASS are not blank: */
#ifndef EXAMPLE_ESP_WIFI_SSID
    #warning "Setting default WiFi SSID: MYSSID_WIFI_CONNECT"
    #define EXAMPLE_ESP_WIFI_SSID "MYSSID_WIFI_CONNECT"
#endif
#ifndef EXAMPLE_ESP_WIFI_PASS
    #warning "Setting default WiFi SSID Password: MYSSID_WIFI_CONNECT"
    #define EXAMPLE_ESP_WIFI_PASS "MYPASSWORD_WIFI_CONNECT"
#endif

/* ESP lwip */
#define EXAMPLE_ESP_MAXIMUM_RETRY  CONFIG_ESP_MAXIMUM_RETRY

int wifi_init_sta(void);

int wifi_show_ip(void);

#endif /* _WIFI_CONNECT_H_ */
