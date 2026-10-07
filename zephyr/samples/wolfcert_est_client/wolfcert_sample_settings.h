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

/* wolfSSL settings for this sample: the set wolfCert ships, plus additions. */

#ifndef WOLFCERT_SAMPLE_SETTINGS_H
#define WOLFCERT_SAMPLE_SETTINGS_H

#include "zephyr/wolfssl_user_settings.h"

#define WOLFSSL_SMALL_STACK

/* P-256 in Thumb-2 assembly on ARMv7-M/ARMv8-M Mainline cores. */
#ifdef CONFIG_ARMV7_M_ARMV8_M_MAINLINE
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_SP_ARM_CORTEX_M_ASM
    #define WOLFSSL_SP_SMALL
#endif

#endif /* WOLFCERT_SAMPLE_SETTINGS_H */
