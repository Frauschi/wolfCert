/*
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCert.
 *
 * wolfCert is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfCert is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfCert.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file log.h
 * Pluggable diagnostic logging. wolfCert stays silent until a callback is
 * installed with wolfcert_set_log_cb.
 */

#ifndef WOLFCERT_LOG_H
#define WOLFCERT_LOG_H

#include <wolfcert/api.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WOLFCERT_LOG_ERROR = 0,
    WOLFCERT_LOG_WARN  = 1,
    WOLFCERT_LOG_INFO  = 2,
    WOLFCERT_LOG_DEBUG = 3
} WolfCertLogLevel;

/* msg is the formatted message, owned by the library and valid only during
 * the call; ctx is the value given to wolfcert_set_log_cb. */
typedef void (*WolfCertLogCb)(WolfCertLogLevel level,
                              const char* module, const char* msg,
                              void* ctx);

WOLFCERT_API void wolfcert_set_log_cb(WolfCertLogCb cb, void* ctx);

/* Highest level forwarded to the callback; default WOLFCERT_LOG_WARN. */
WOLFCERT_API void wolfcert_set_log_level(WolfCertLogLevel lvl);
WOLFCERT_API WolfCertLogLevel wolfcert_log_level(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_LOG_H */
