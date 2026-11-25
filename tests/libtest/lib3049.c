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
#include "first.h"
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#include <signal.h>

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT) && \
  defined(RLIMIT_FSIZE) && defined(SIGXFSZ)

static CURLcode save_caches(const char *url, const char *hsts,
                            const char *alt, bool limited)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;

  easy_init(curl);
  easy_setopt(curl, CURLOPT_URL, url);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, tutil_throwaway_cb);
  easy_setopt(curl, CURLOPT_HSTS, hsts);
  easy_setopt(curl, CURLOPT_ALTSVC, alt);
  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;

  if(limited) {
    struct rlimit original, limit;
    void (*handler)(int);

    if(getrlimit(RLIMIT_FSIZE, &original)) {
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
    limit = original;
    limit.rlim_cur = 40;
    handler = signal(SIGXFSZ, SIG_IGN);
    if(setrlimit(RLIMIT_FSIZE, &limit)) {
      signal(SIGXFSZ, handler);
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }

    curl_easy_cleanup(curl);
    curl = NULL;
    if(setrlimit(RLIMIT_FSIZE, &original))
      result = TEST_ERR_FAILURE;
    signal(SIGXFSZ, handler);
  }

test_cleanup:
  curl_easy_cleanup(curl);
  return result;
}

static CURLcode test_lib3049(const char *URL)
{
  CURLcode result = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  result = save_caches(URL, libtest_arg2, libtest_arg3, FALSE);
  if(!result)
    result = save_caches(URL, libtest_arg4, libtest_arg5, TRUE);

test_cleanup:
  curl_global_cleanup();
  return result;
}

#else

static CURLcode test_lib3049(const char *URL)
{
  (void)URL;
  return CURLE_OK;
}

#endif
