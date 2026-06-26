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

/*
 * Covers the built-in POSIX transport (wolfcert_posix_connect), in particular
 * the timeout path: a positive timeout_ms must drive the non-blocking
 * connect + poll machinery (success case against a local listener) and must
 * bound a connect to an unreachable host instead of hanging on the OS default
 * (~75s).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>
#include <wolfcert/http.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static long mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(void)
{
    /* Success path with a positive timeout: stand up a loopback listener and
     * connect to it. timeout_ms > 0 exercises the non-blocking connect + poll
     * + SO_ERROR branch deterministically. */
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(ls >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = 0;
    REQUIRE(bind(ls, (struct sockaddr*)&sa, sizeof(sa)) == 0);
    REQUIRE(listen(ls, 8) == 0);
    socklen_t slen = sizeof(sa);
    REQUIRE(getsockname(ls, (struct sockaddr*)&sa, &slen) == 0);
    int port = ntohs(sa.sin_port);

    int fd = wolfcert_posix_connect("127.0.0.1", port, 1000, NULL);
    REQUIRE(fd >= 0);
    close(fd);
    close(ls);

    /* Timeout path: an unroutable address must fail (fd < 0) and return fast.
     * Without the timeout this would block on the OS default (~75s); we only
     * assert it stays well under that, so the test is robust whether the host
     * times out at ~250ms or fast-fails with no route. */
    long t0 = mono_ms();
    int fd2 = wolfcert_posix_connect("10.255.255.1", 9, 250, NULL);
    long elapsed = mono_ms() - t0;
    REQUIRE(fd2 < 0);
    REQUIRE(elapsed < 3000);

    printf("OK (unreachable connect returned in %ldms)\n", elapsed);
    return 0;
}
