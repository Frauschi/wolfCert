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

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE   /* expose memmem/strcasestr/INADDR_LOOPBACK on macOS */

#include <wolfcert/wolfcert.h>
#include "internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#define REQUIRE(cond) \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static int test_url_parser(void)
{
    WolfCertUrl u;
    REQUIRE(wolfcert_http_url_parse("https://ca.example.com/.well-known/est/cacerts", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.scheme, "https") == 0);
    REQUIRE(strcmp(u.host, "ca.example.com") == 0);
    REQUIRE(u.port == 443);
    REQUIRE(strcmp(u.path, "/.well-known/est/cacerts") == 0);
    REQUIRE(u.tls == 1);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("http://localhost:8080/scep", &u, NULL) == WOLFCERT_OK);
    REQUIRE(u.port == 8080);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("http://host", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.path, "/") == 0);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("https://[::1]:8443/p", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.host, "::1") == 0);
    REQUIRE(u.port == 8443);
    wolfcert_http_url_free(&u);

    REQUIRE(wolfcert_http_url_parse("ftp://nope/", &u, NULL) == WOLFCERT_ERR_UNSUPPORTED);

    /* A URL with no explicit scheme defaults to TLS (https). */
    REQUIRE(wolfcert_http_url_parse("ca.example.com:8443/p", &u, NULL) == WOLFCERT_OK);
    REQUIRE(strcmp(u.scheme, "https") == 0);
    REQUIRE(strcmp(u.host, "ca.example.com") == 0);
    REQUIRE(u.port == 8443);
    REQUIRE(u.tls == 1);
    wolfcert_http_url_free(&u);
    return 0;
}

struct srv_ctx { int port; };

static void* srv_thread(void* arg)
{
    struct srv_ctx* sc = (struct srv_ctx*)arg;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return NULL;
    int yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(0),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(ls);
        return NULL;
    }
    if (listen(ls, 1) < 0) {
        close(ls);
        return NULL;
    }
    socklen_t slen = sizeof(sa);
    getsockname(ls, (struct sockaddr*)&sa, &slen);
    sc->port = ntohs(sa.sin_port);

    int cs = accept(ls, NULL, NULL);
    close(ls);
    if (cs < 0)
        return NULL;

    char buf[4096];
    size_t n = 0;
    while (n < sizeof(buf) - 1) {
        ssize_t r = recv(cs, buf + n, sizeof(buf) - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t)r;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
    }

    const char* response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "6\r\nhello \r\n"
        "9\r\nwolfCert\n\r\n"
        "0\r\n\r\n";
    send(cs, response, strlen(response), 0);
    shutdown(cs, SHUT_WR);
    close(cs);
    return NULL;
}

static int test_loopback_http(void)
{
    struct srv_ctx sc = { 0 };
    pthread_t tid;
    REQUIRE(pthread_create(&tid, NULL, srv_thread, &sc) == 0);
    for (int i = 0; i < 200 && sc.port == 0; ++i) {
        const struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    REQUIRE(sc.port != 0);

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/test", sc.port);
    const char* body = "ping";
    WolfCertHttpRequest req = {
        .method = "POST", .url = url,
        .content_type = "application/octet-stream",
        .body = (const uint8_t*)body, .body_len = strlen(body),
        .basic_user = "alice", .basic_pass = "secret",
    };
    WolfCertHttpResponse resp = { 0 };
    REQUIRE(wolfcert_http_request(&req, &resp) == WOLFCERT_OK);
    REQUIRE(resp.status_code == 200);
    REQUIRE(resp.body_len == 15);
    REQUIRE(memcmp(resp.body, "hello wolfCert\n", 15) == 0);
    wolfcert_http_response_free(&resp);
    pthread_join(tid, NULL);
    return 0;
}

int main(void)
{
    REQUIRE(wolfcert_init(NULL) == WOLFCERT_OK);
    if (test_url_parser())
        return 1;
    if (test_loopback_http())
        return 1;
    wolfcert_cleanup();
    printf("OK\n");
    return 0;
}
