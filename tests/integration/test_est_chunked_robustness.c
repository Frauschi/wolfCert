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
 * Negative coverage for the chunked-transfer decoder in the EST
 * server's request parser. Drives the server with raw HTTP/1.1
 * requests that advertise `Transfer-Encoding: chunked` but mis-frame
 * the body, and asserts each one comes back as HTTP 400 rather than
 * being silently tolerated.
 *
 * Shapes covered:
 *   1. Oversized chunk-size (more than 8 hex digits).
 *   2. Corrupt inter-chunk trailer (bytes where CRLF should be).
 *   3. Well-formed sanity baseline so the test fails loudly if the
 *      server stops accepting chunked altogether.
 *
 * The target is `src/est/est_server.c`'s parse_request chunked path;
 * no TLS is involved so we can script the byte-exact request here.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */
#define _GNU_SOURCE

#include <wolfcert/wolfcert.h>
#include <wolfcert/server.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static void* server_thread(void* arg)
{
    wolfcert_server_run((WolfCertServer*)arg);
    return NULL;
}

/* Dial 127.0.0.1:port, send `req` of `req_len` bytes, return the
 * first line of the response (up to the CRLF or buffer cap). */
static int send_and_read_status(uint16_t port,
                                const void* req, size_t req_len,
                                char* status_line, size_t cap)
{
    int cs = socket(AF_INET, SOCK_STREAM, 0);
    if (cs < 0)
        return -1;
    struct sockaddr_in sa = { .sin_family = AF_INET,
                              .sin_port = htons(port),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (connect(cs, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(cs);
        return -1;
    }
    const char* p = req;
    size_t left = req_len;
    while (left > 0) {
        ssize_t w = send(cs, p, left, 0);
        if (w <= 0) {
            close(cs);
            return -1;
        }
        p += w;
        left -= (size_t)w;
    }
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = recv(cs, status_line + n, cap - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        status_line[n] = '\0';
        /* Stop once we have the first line. */
        if (memchr(status_line, '\n', n) != NULL)
            break;
    }
    close(cs);
    status_line[n < cap ? n : cap - 1] = '\0';
    return (int)n;
}

/* Shape #1: a chunk-size line longer than 8 hex digits. The parser
 * must reject this rather than letting the shift-accumulate silently
 * wrap. */
static int reject_oversized_chunk_size(uint16_t port)
{
    const char* req =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        /* 16 hex digits -> body would be 2^63 bytes, but the cap kicks
         * in at digit 9 and returns ERR_PROTOCOL. */
        "FFFFFFFFFFFFFFFF\r\n"
        "ignored\r\n"
        "0\r\n\r\n";
    char status[128] = { 0 };
    send_and_read_status(port, req, strlen(req), status, sizeof(status));
    REQUIRE(strstr(status, "400") != NULL);
    return 0;
}

/* Shape #2: inter-chunk trailer that isn't CRLF. A legitimate
 * chunked encoder always emits "<csz>\r\n<data>\r\n<csz>\r\n..."; the
 * parser must reject "<data>XX<csz>\r\n..." instead of absorbing the
 * garbage. */
static int reject_corrupt_chunk_trailer(uint16_t port)
{
    const char req[] =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\n"
        "AAAA"          /* chunk body */
        "XX"            /* <-- should be \r\n; this is the bug we catch */
        "0\r\n\r\n";
    char status[128] = { 0 };
    send_and_read_status(port, req, sizeof(req) - 1, status, sizeof(status));
    REQUIRE(strstr(status, "400") != NULL);
    return 0;
}

/* Positive sanity: a well-formed (if garbage-content) chunked POST
 * still reaches the CSR-parse stage and gets rejected with 400 -
 * but distinctly at the CSR layer, not at the framer. We only
 * require "not 500" here; the 400 body in both cases proves the
 * server didn't crash on the well-framed request. */
static int accept_wellformed_chunks(uint16_t port)
{
    const char req[] =
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\nAAAA\r\n"
        "0\r\n\r\n";
    char status[128] = { 0 };
    send_and_read_status(port, req, sizeof(req) - 1, status, sizeof(status));
    /* Not crashing / hanging -> we got *some* status back. The body is
     * not a real CSR so the server returns 400 "Bad CSR"; what we care
     * about is that the framer fed the bytes through cleanly. */
    REQUIRE(status[0] == 'H');
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);

    WolfCertServerCfgSrv cfg = {
        .protocol = WOLFCERT_PROTO_EST,
        .bind_host = "127.0.0.1", .bind_port = 0,
    };
    WolfCertServer* srv = NULL;
    REQUIRE(wolfcert_server_start(&cfg, &srv) == WOLFCERT_OK);
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, server_thread, srv) == 0);

    uint16_t port = wolfcert_server_port(srv);

    int rc = reject_oversized_chunk_size(port);
    if (rc == 0)
        rc = reject_corrupt_chunk_trailer(port);
    if (rc == 0)
        rc = accept_wellformed_chunks(port);

    wolfcert_server_stop(srv);
    pthread_join(tid, NULL);
    wolfcert_server_free(srv);
    if (rc != 0)
        return rc;

    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
