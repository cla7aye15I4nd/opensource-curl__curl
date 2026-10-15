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
#include "cfilters.h"
#include "vtls/vtls.h"
#include "vtls/vtls_int.h"

#ifdef USE_SSL
static CURLcode send_result;
static size_t send_calls;
static const uint8_t *send_expected;
static size_t send_len;

static CURLcode blocked_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                              const void *mem, size_t len, size_t *pnwritten)
{
  (void)cf;
  (void)data;
  send_calls++;
  fail_unless(mem == send_expected && len == send_len,
              "TLS backend received wrong request suffix");
  *pnwritten = 0;
  return send_result;
}
#endif

static CURLcode test_unit3423(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
#ifdef USE_SSL
  struct Curl_easy *data;
  struct Curl_ssl backend;
  struct ssl_connect_data ctx;
  struct Curl_cfilter cf;
  static const uint8_t request[] = "acceptedremaining";
  size_t written = 0;
  CURLcode result;

  abort_unless(!curl_global_init(CURL_GLOBAL_ALL), "global init");
  data = curl_easy_init();
  abort_unless(data, "easy init");
  memset(&backend, 0, sizeof(backend));
  memset(&ctx, 0, sizeof(ctx));
  memset(&cf, 0, sizeof(cf));
  backend.send_plain = blocked_send;
  ctx.ssl_impl = &backend;
  ctx.state = ssl_connection_complete;
  cf.cft = &Curl_cft_ssl;
  cf.ctx = &ctx;

  ctx.earlydata_skip = 8;
  send_expected = request + 8;
  send_len = sizeof(request) - 1 - 8;
  send_result = CURLE_AGAIN;
  result = cf.cft->do_send(&cf, data, request, sizeof(request) - 1,
                          FALSE, &written);
  fail_unless(!result && written == 8,
              "accepted early-data prefix lost after write stall");
  fail_unless(!ctx.earlydata_skip, "accepted prefix was not consumed");

  result = cf.cft->do_send(&cf, data, request + 8, send_len, FALSE, &written);
  fail_unless(result == CURLE_AGAIN && !written,
              "ordinary blocked write must remain retryable");

  ctx.earlydata_skip = 8;
  send_result = CURLE_SEND_ERROR;
  result = cf.cft->do_send(&cf, data, request, sizeof(request) - 1,
                          FALSE, &written);
  fail_unless(result == CURLE_SEND_ERROR, "fatal TLS error was hidden");
  fail_unless(send_calls == 3, "wrong number of backend sends");

  ctx.earlydata_skip = sizeof(request) - 1;
  result = cf.cft->do_send(&cf, data, request, sizeof(request) - 1,
                          FALSE, &written);
  fail_unless(!result && written == sizeof(request) - 1 && send_calls == 3,
              "fully accepted early data must not be sent again");
  curl_easy_cleanup(data);
  curl_global_cleanup();
#endif
  UNITTEST_END_SIMPLE
}
