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
 * Default POSIX/BSD-sockets transport. This is the built-in implementation of
 * WolfCertConnectFn used when a config leaves connect_cb NULL. It lives in its
 * own translation unit so the core HTTP/TLS logic depends only on the connect
 * callback, and so an application targeting a platform without BSD sockets can
 * supply its own transport and leave this out of the link.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <wolfcert/http.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static long mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Connect `fd` to `addr`, giving up after timeout_ms (<= 0 = block until the
 * OS gives up). Returns 0 on success, -1 on error/timeout. The socket is left
 * in blocking mode on success so the rest of the stack (and wolfSSL) sees a
 * normal fd. */
static int connect_timeout(int fd, const struct sockaddr* addr, socklen_t alen,
                           int timeout_ms)
{
    if (timeout_ms <= 0) {
        int rc;
        do {
            rc = connect(fd, addr, alen);
        }
        while (rc != 0 && errno == EINTR);

        return rc == 0 ? 0 : -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        /* nothing changed; nothing to restore */
        return -1;
    }

    int rc = connect(fd, addr, alen);
    if (rc != 0 && errno == EINPROGRESS) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr;
        do {
            pr = poll(&pfd, 1, timeout_ms);
        }
        while (pr < 0 && errno == EINTR);

        if (pr <= 0) {
            /* timeout (0) or poll error (<0) */
            rc = -1;
        }
        else {
            int err = 0;
            socklen_t elen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0)
                rc = -1;
            else
                rc = 0;
        }
    }
    else if (rc != 0) {
        /* immediate failure */
        rc = -1;
    }

    /* restore blocking mode */
    (void)fcntl(fd, F_SETFL, flags);

    return rc;
}

int wolfcert_posix_connect(const char* host, int port, int timeout_ms, void* ctx)
{
    (void)ctx;
    if (host == NULL)
        return -1;

    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%d", port);

    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_s, &hints, &res) != 0)
        return -1;

    /* timeout_ms bounds the whole connect, not each candidate address: with a
     * multi-homed host we shrink the per-attempt budget by what already
     * elapsed so the total stays within the caller's deadline. */
    long deadline = (timeout_ms > 0) ? mono_ms() + timeout_ms : 0;

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        int attempt_ms = timeout_ms;
        if (timeout_ms > 0) {
            attempt_ms = (int)(deadline - mono_ms());
            if (attempt_ms <= 0) {
                /* budget exhausted */
                break;
            }
        }
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;

        if (connect_timeout(fd, rp->ai_addr, rp->ai_addrlen, attempt_ms) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}
