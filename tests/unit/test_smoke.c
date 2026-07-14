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

#include <wolfcert/wolfcert.h>
#include "../test_static_mem.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    if (test_static_mem_init() != 0) {
        fprintf(stderr, "static mem init failed\n");
        return 1;
    }
    if (wolfcert_init(NULL) != WOLFCERT_OK) {
        fprintf(stderr, "wolfcert_init failed\n");
        return 1;
    }
    const char* v = wolfcert_version_string();
    if (v == NULL || strlen(v) == 0) {
        wolfcert_cleanup();
        return 1;
    }
    if (strcmp(wolfcert_strerror(WOLFCERT_OK), "ok") != 0) {
        wolfcert_cleanup();
        return 1;
    }
    printf("wolfCert %s\n", v);
    wolfcert_cleanup();
    return 0;
}
