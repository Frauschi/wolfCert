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
 * @file status.h
 * Extended error-state access.
 *
 * wolfcert functions return a small WOLFCERT_ERR_* code. That code is
 * usually enough, but when diagnosing a failed enrollment it helps to
 * know *which* internal step failed and what the underlying wolfSSL
 * error was. The library records those details in thread-local storage
 * whenever it maps an error; callers retrieve them with
 * wolfcert_last_error_message() and wolfcert_last_wolfssl_err().
 *
 * Thread-local means the extended state is per-thread on POSIX and
 * single-threaded-safe on freestanding builds without TLS.
 */

#ifndef WOLFCERT_STATUS_H
#define WOLFCERT_STATUS_H

#include <wolfcert/api.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Human-readable message describing the most recent error encountered on
 * this thread. Returns a static "" string if nothing has gone wrong.
 * The returned pointer is valid until the next wolfCert call on this
 * thread. */
WOLFCERT_API const char* wolfcert_last_error_message(void);

/* Underlying wolfSSL error code (as returned by the wolfSSL function
 * that failed). 0 if the last wolfCert failure wasn't a crypto failure
 * or if no failure has occurred. */
WOLFCERT_API int wolfcert_last_wolfssl_err(void);

/* Reset the thread-local error state. */
WOLFCERT_API void wolfcert_clear_error(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_STATUS_H */
