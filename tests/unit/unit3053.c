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

#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP) && \
  !defined(CURL_DISABLE_NETRC)
#include "creds.h"
#include "netrc.h"
#endif

static CURLcode test_unit3053(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP) && \
  !defined(CURL_DISABLE_NETRC)
  struct Curl_easy *data;
  struct Curl_creds *creds = NULL;
  struct store_netrc store;
  CURLcode result;
  NETRCcode rc;

  abort_unless(SetCurrentDirectoryA(arg), "could not enter fixture directory");
  abort_unless(SetEnvironmentVariableA("NETRC", "missing"),
               "could not set NETRC");
  abort_unless(SetEnvironmentVariableA("HOME", "home"), "could not set HOME");

  global_init(CURL_GLOBAL_ALL);
  data = curl_easy_init();
  if(!data) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }

  Curl_netrc_init(&store);
  rc = Curl_netrc_scan(data, &store, "example.com", NULL, NULL, &creds);
  fail_unless(rc == NETRC_FILE_MISSING, "NETRC override should fail");
  fail_unless(!creds, "override must not load fallback credentials");

  rc = Curl_netrc_scan(data, &store, "example.com", NULL,
                       "home/_netrc", &creds);
  fail_unless(rc == NETRC_OK, "explicit file should override NETRC");
  fail_unless(!strcmp(Curl_creds_user(creds), "home-user"),
              "expected explicit credentials");
  Curl_creds_unlink(&creds);
  Curl_netrc_cleanup(&store);

  if(SetEnvironmentVariableA("NETRC", NULL)) {
    Curl_netrc_init(&store);
    rc = Curl_netrc_scan(data, &store, "example.com", NULL, NULL, &creds);
    fail_unless(rc == NETRC_OK, "expected legacy fallback under HOME");
    fail_unless(!strcmp(Curl_creds_user(creds), "home-user"),
                "expected home directory credentials");
    Curl_creds_unlink(&creds);
    Curl_netrc_cleanup(&store);
  }
  else
    fail("could not remove NETRC");

  curl_easy_cleanup(data);
  curl_global_cleanup();
#endif

  UNITTEST_END_SIMPLE
}
