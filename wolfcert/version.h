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

#ifndef WOLFCERT_VERSION_H
#define WOLFCERT_VERSION_H

#define WOLFCERT_VERSION_MAJOR 0
#define WOLFCERT_VERSION_MINOR 1
#define WOLFCERT_VERSION_PATCH 0
#define WOLFCERT_VERSION_STRING "0.1.0"

#include <wolfcert/api.h>

#ifdef __cplusplus
extern "C" {
#endif

WOLFCERT_API const char* wolfcert_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCERT_VERSION_H */
