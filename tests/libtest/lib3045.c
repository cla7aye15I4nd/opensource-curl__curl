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
 ***************************************************************************/
#include "first.h"

#ifdef USE_OPENSSL
#include <openssl/ssl.h>

static CURLcode t3045_add_ca(CURL *curl, void *ctx, void *clientp)
{
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  (void)curl;
  if(X509_STORE_load_locations(store, clientp, NULL) != 1)
    return CURLE_SSL_CACERT_BADFILE;
  return CURLE_OK;
}

static CURLcode t3045_transfer(CURLM *multi, const char *URL, bool callback)
{
  CURL *curl = NULL;
  CURLMsg *msg;
  CURLcode result = CURLE_OK;
  CURLMcode mresult;
  int running, pending;

  easy_init(curl);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_CAINFO, libtest_arg2);
  easy_setopt(curl, CURLOPT_CA_CACHE_TIMEOUT, 60L);
  easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0L);
  easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
  easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  if(callback) {
    easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, t3045_add_ca);
    easy_setopt(curl, CURLOPT_SSL_CTX_DATA, libtest_arg3);
  }

  result = CURLE_FAILED_INIT;
  mresult = curl_multi_add_handle(multi, curl);
  if(mresult)
    goto test_cleanup;

  do {
    mresult = curl_multi_perform(multi, &running);
    if(!mresult && running)
      mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);
  } while(!mresult && running);

  msg = curl_multi_info_read(multi, &pending);
  if(msg && msg->msg == CURLMSG_DONE)
    result = msg->data.result;
  curl_multi_remove_handle(multi, curl);

test_cleanup:
  curl_easy_cleanup(curl);
  return result;
}
#endif

static CURLcode test_lib3045(const char *URL)
{
#ifdef USE_OPENSSL
  CURLM *multi = NULL;
  CURLcode result = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  multi_init(multi);

  result = t3045_transfer(multi, URL, TRUE);
  if(result)
    goto test_cleanup;

  result = t3045_transfer(multi, URL, FALSE);
  if(result == CURLE_PEER_FAILED_VERIFICATION)
    result = CURLE_OK;
  else {
    curl_mfprintf(stderr, "Expected certificate rejection, got %d\n",
                  (int)result);
    result = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:
  curl_multi_cleanup(multi);
  curl_global_cleanup();
  return result;
#else
  (void)URL;
  return CURLE_NOT_BUILT_IN;
#endif
}
