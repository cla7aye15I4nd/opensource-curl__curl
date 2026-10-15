/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "unitcheck.h"
#include "urldata.h"
#include "cookie.h"

static CURLcode test_unit3425(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
  static const char *hosts[] = {
    "localhost", "LOCALHOST", "127.0.0.1", "::1"
  };
  struct Curl_easy *data;
  struct Curl_peer *origin = NULL;
  struct connectdata conn;
  size_t i;

  abort_unless(!curl_global_init(CURL_GLOBAL_ALL), "global init");
  data = curl_easy_init();
  abort_unless(data, "easy init");
  memset(&conn, 0, sizeof(conn));
  abort_unless(!Curl_peer_create(data, &Curl_scheme_http,
                                 "localhost", 80, &origin), "HTTP origin");
  data->state.origin = origin;
  data->conn = &conn;
  for(i = 0; i < CURL_ARRAYSIZE(hosts); ++i) {
    fail_unless(Curl_secure_context(data, hosts[i]),
                "direct HTTP loopback lost secure context");
#ifndef CURL_DISABLE_PROXY
    conn.http_proxy.peer = origin;
    fail_unless(!Curl_secure_context(data, hosts[i]),
                "HTTP proxy inherited loopback secure context");
    conn.http_proxy.peer = NULL;
    conn.socks_proxy.peer = origin;
    fail_unless(!Curl_secure_context(data, hosts[i]),
                "SOCKS proxy inherited loopback secure context");
    conn.socks_proxy.peer = NULL;
#endif
  }
  fail_unless(!Curl_secure_context(data, "example.com"),
              "ordinary plaintext origin became secure");
  Curl_peer_unlink(&data->state.origin);
  origin = NULL;
  abort_unless(!Curl_peer_create(data, &Curl_scheme_https,
                                 "example.com", 443, &origin), "HTTPS origin");
  data->state.origin = origin;
#ifndef CURL_DISABLE_PROXY
  conn.http_proxy.peer = origin;
  conn.socks_proxy.peer = origin;
#endif
  fail_unless(Curl_secure_context(data, "example.com"),
              "HTTPS over a proxy lost secure context");
  data->conn = NULL;
  curl_easy_cleanup(data);
  curl_global_cleanup();
#endif
  UNITTEST_END_SIMPLE
}
