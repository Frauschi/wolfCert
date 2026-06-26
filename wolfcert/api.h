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

#ifndef WOLFCERT_API_H
#define WOLFCERT_API_H

/* WOLFCERT_TEST_VIS: visibility annotation for symbols that are NOT part
 * of the public ABI but that in-tree tests need to reach. When the library
 * is built with WOLFCERT_BUILD_TESTING the symbols are exported with
 * default visibility; otherwise they stay hidden. */
#if defined(WOLFCERT_BUILD_TESTING) && (defined(__GNUC__) || defined(__clang__))
#  define WOLFCERT_TEST_VIS __attribute__((visibility("default")))
#else
#  define WOLFCERT_TEST_VIS
#endif


/* Visibility / DLL export annotation for public wolfCert symbols. */

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(WOLFCERT_BUILD_DLL)
#    define WOLFCERT_API __declspec(dllexport)
#  elif defined(WOLFCERT_USE_DLL)
#    define WOLFCERT_API __declspec(dllimport)
#  else
#    define WOLFCERT_API
#  endif
#else
#  if defined(__GNUC__) && __GNUC__ >= 4
#    define WOLFCERT_API __attribute__((visibility("default")))
#  else
#    define WOLFCERT_API
#  endif
#endif

#endif /* WOLFCERT_API_H */
