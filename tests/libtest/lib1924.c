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

static CURLcode test_lib1924(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *curl = NULL;
  CURLSH *share = NULL;
  int i;

  global_init(CURL_GLOBAL_ALL);

  share = curl_share_init();
  if(!share) {
    result = CURLE_OUT_OF_MEMORY;
    goto test_cleanup;
  }
  if(curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_HSTS)) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  for(i = 0; i < 2; ++i) {
    easy_init(curl);
    easy_setopt(curl, CURLOPT_URL, URL);
    easy_setopt(curl, CURLOPT_SHARE, share);
    easy_setopt(curl, CURLOPT_HSTS, libtest_arg2);

    if(i)
      easy_setopt(curl, CURLOPT_HSTS_CTRL, 0L);
    else
      easy_setopt(curl, CURLOPT_SHARE, NULL);

    result = curl_easy_perform(curl);
    if(result)
      goto test_cleanup;
    curl_easy_cleanup(curl);
    curl = NULL;
  }

test_cleanup:
  curl_easy_cleanup(curl);
  if(share)
    curl_share_cleanup(share);
  curl_global_cleanup();
  return result;
}
