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

#if !defined(CURL_DISABLE_HTTP) || !defined(CURL_DISABLE_MQTT)
static bool t3308_fail_alloc;
static bool t3308_alloc_failed;

static void *t3308_malloc(size_t size)
{
  if(t3308_fail_alloc) {
    t3308_fail_alloc = FALSE;
    t3308_alloc_failed = TRUE;
    return NULL;
  }
  /* !checksrc! disable BANNEDFUNC 1 */
  return malloc(size);
}

static char *t3308_strdup(const char *s)
{
  size_t size = strlen(s) + 1;
  char *copy = t3308_malloc(size);
  if(copy)
    memcpy(copy, s, size);
  return copy;
}

static void t3308_cleanup(CURL *easy)
{
  t3308_fail_alloc = FALSE;
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}
#endif

static CURLcode test_unit3308(const char *arg)
{
#if !defined(CURL_DISABLE_HTTP) || !defined(CURL_DISABLE_MQTT)
  CURL *easy = NULL;
  struct Curl_easy *data;
  CURLcode result;

  UNITTEST_BEGIN_SIMPLE

  result = curl_global_init_mem(CURL_GLOBAL_ALL, t3308_malloc, free, realloc,
                                t3308_strdup, calloc);
  abort_unless(result == CURLE_OK, "global init failed");
  easy = curl_easy_init();
  abort_unless(easy, "easy init failed");
  data = easy;
  result = curl_easy_setopt(easy, CURLOPT_COPYPOSTFIELDS, "original");
  abort_unless(result == CURLE_OK, "setting initial POST data failed");

  t3308_alloc_failed = FALSE;
  t3308_fail_alloc = TRUE;
  result = curl_easy_setopt(easy, CURLOPT_COPYPOSTFIELDS, "replacement");
  t3308_fail_alloc = FALSE;
  abort_unless(t3308_alloc_failed && result == CURLE_OUT_OF_MEMORY,
               "replacement allocation did not fail");
  abort_unless(data->set.str_copypostfields &&
               data->set.postfields == data->set.str_copypostfields,
               "allocation failure lost ownership of the original data");
  fail_unless(!strcmp(data->set.postfields, "original"),
              "allocation failure changed the POST data");

  result = curl_easy_setopt(easy, CURLOPT_COPYPOSTFIELDS, "replacement");
  abort_unless(result == CURLE_OK, "replacement retry failed");
  fail_unless(!strcmp(data->set.postfields, "replacement"),
              "successful retry did not replace the POST data");

  UNITTEST_END(t3308_cleanup(easy))
#else
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
#endif
}
