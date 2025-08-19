/*
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

/* common Espressif time_helper v5.6.3.001 */

#ifndef _TIME_HELPER_H
#define _TIME_HELPER_H

/* ESP-IDF uses a 64-bit signed integer to represent time_t starting from release v5.0
 * See: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/system_time.html#year-2036-and-2038-overflow-issues
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <esp_err.h>

/* a function to show the current data and time */
esp_err_t  esp_show_current_datetime();

/* worst case, if GitHub time not available, used fixed time */
esp_err_t  set_fixed_default_time(void);

/* set time from string (e.g. GitHub commit time) */
esp_err_t set_time_from_string(const char* time_buffer);

/* set time from NTP servers,
 * also initially calls set_fixed_default_time or set_time_from_string */
esp_err_t  set_time(void);

/* wait NTP_RETRY_COUNT seconds before giving up on NTP time */
esp_err_t  set_time_wait_for_ntp(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef _TIME_HELPER_H */
