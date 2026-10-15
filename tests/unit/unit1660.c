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

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_HSTS)
#include "urldata.h"
#include "hsts.h"

static CURLSTScode readonly_write(CURL *easy, struct curl_hstsentry *entry,
                                  struct curl_index *index, void *userdata)
{
  unsigned int *calls = userdata;
  (void)easy;
  (void)entry;
  (void)index;
  ++*calls;
  return CURLSTS_OK;
}

static void showsts(struct stsentry *e, const char *chost)
{
  if(!e)
    curl_mprintf("'%s' is not HSTS\n", chost);
  else {
    curl_mprintf("%s [%s]: %" CURL_FORMAT_CURL_OFF_T "%s\n",
                 chost, e->host, e->expires,
                 e->includeSubDomains ? " includeSubDomains" : "");
  }
}

static CURLcode test_unit1660(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  struct testit {
    const char *host;
    const char *chost;     /* if non-NULL, use to lookup with */
    const char *hdr;       /* if NULL, do the lookup */
    const CURLcode result; /* parse result */
  };

  static const struct testit headers[] = {
    /* two entries read from disk cache, verify first */
    { "-", "readfrom.example", NULL, CURLE_OK },
    { "-", "old.example", NULL, CURLE_OK },
    /* delete the remaining one read from disk */
    { "readfrom.example", NULL, "max-age=\"0\"", CURLE_OK },

    { "example.com", NULL, "max-age=\"31536000\"\r\n", CURLE_OK },
    { "example.com", NULL, "max-age=\"21536000\"\r\n", CURLE_OK },
    { "example.com", NULL, "max-age=\"21536000\"; \r\n", CURLE_OK },
    { "example.com", NULL, "max-age=\"21536000\"; includeSubDomains\r\n",
      CURLE_OK },
    { "example.org", NULL, "max-age=\"31536000\"\r\n", CURLE_OK },
    { "this.example", NULL, "max=\"31536\";", CURLE_BAD_FUNCTION_ARGUMENT },
    { "this.example", NULL, "max-age=\"31536", CURLE_BAD_FUNCTION_ARGUMENT },
    { "this.example", NULL, "max-age=31536\"", CURLE_OK },
    /* max-age=0 removes the entry */
    { "this.example", NULL, "max-age=0", CURLE_OK },
    { "another.example", NULL, "includeSubDomains; ",
      CURLE_BAD_FUNCTION_ARGUMENT },

    /* Two max-age is illegal */
    { "example.com", NULL,
      "max-age=\"21536000\"; includeSubDomains; max-age=\"3\";",
      CURLE_BAD_FUNCTION_ARGUMENT },
    /* Two includeSubDomains is illegal */
    { "2.example.com", NULL,
      "max-age=\"21536000\"; includeSubDomains; includeSubDomains;",
      CURLE_BAD_FUNCTION_ARGUMENT },
    /* use an unknown directive "include" that should be ignored */
    { "3.example.com", NULL,
      "max-age=\"21536000\"; include; includeSubDomains;", CURLE_OK },
    /* remove the "3.example.com" one, should still match the example.com */
    { "3.example.com", NULL, "max-age=\"0\"; includeSubDomains;", CURLE_OK },
    { "-", "foo.example.com", NULL, CURLE_OK },
    { "-", "foo.xample.com", NULL, CURLE_OK },

    /* should not match */
    { "example.net", "forexample.net", "max-age=\"31536000\"\r\n", CURLE_OK },

    /* should not match either, since forexample.net is not in the example.net
       domain */
    { "example.net", "forexample.net",
      "max-age=\"31536000\"; includeSubDomains\r\n", CURLE_OK },
    /* remove example.net again */
    { "example.net", NULL, "max-age=\"0\"; includeSubDomains\r\n", CURLE_OK },

    /* make this live for 7 seconds */
    { "expire.example", NULL, "max-age=\"7\"\r\n", CURLE_OK },
    { NULL, NULL, NULL, CURLE_OK }
  };

  CURLcode result;
  struct stsentry *e;
  struct hsts *h = Curl_hsts_init();
  int i;
  const char *chost;
  struct Curl_easy *easy;
  struct Curl_easy *clone;
  struct Curl_easy *writer;
  CURLSH *share;
  char savename[256];
  unsigned int write_calls = 0;

  abort_unless(h, "Curl_hsts_init()");

  curl_global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  if(!easy) {
    Curl_hsts_cleanup(&h);
    curl_global_cleanup();
    abort_unless(easy, "curl_easy_init()");
  }

  result = curl_easy_setopt(easy, CURLOPT_HSTS_CTRL,
                            CURLHSTS_ENABLE | CURLHSTS_READONLYFILE);
  fail_unless(!result, "could not set read-only HSTS");
  fail_unless(easy->hsts &&
              easy->set.hsts_readonly,
              "HSTS cache did not retain read-only policy");
  clone = curl_easy_duphandle(easy);
  abort_unless(clone, "could not duplicate HSTS handle");
  fail_unless(clone->hsts &&
              clone->set.hsts_readonly,
              "duplicate lost read-only HSTS policy");
  share = curl_share_init();
  writer = curl_easy_init();
  abort_unless(share && writer, "HSTS share setup");
  fail_unless(!curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_HSTS),
              "enable HSTS sharing");
  fail_unless(!curl_easy_setopt(clone, CURLOPT_SHARE, share), "attach clone");
  fail_unless(!curl_easy_setopt(writer, CURLOPT_SHARE, share),
              "attach writer");
  fail_unless(!curl_easy_setopt(writer, CURLOPT_HSTS_CTRL, CURLHSTS_ENABLE),
              "configure writable shared HSTS handle");
  fail_unless(clone->set.hsts_readonly && !writer->set.hsts_readonly,
              "shared cache replaced per-handle file policy");
  {
    FILE *fp;
    curl_msnprintf(savename, sizeof(savename), "%s.readonly", arg);
    fp = curlx_fopen(savename, "wb");
    abort_unless(fp, "could not create HSTS marker");
    fputs("k", fp);
    curlx_fclose(fp);
    fail_unless(!Curl_hsts_parse(clone->hsts, "readonly.example",
                                 "max-age=31536000"), "learn HSTS policy");
    curl_easy_setopt(clone, CURLOPT_HSTSWRITEFUNCTION, readonly_write);
    curl_easy_setopt(clone, CURLOPT_HSTSWRITEDATA, &write_calls);
    fail_unless(!Curl_hsts_save(clone, clone->hsts, savename), "HSTS save");
    fail_unless(write_calls, "read-only file suppressed HSTS write callback");
    fp = curlx_fopen(savename, "rb");
    abort_unless(fp, "could not read HSTS marker");
    fail_unless(fgetc(fp) == 'k' && fgetc(fp) == EOF,
                "HSTS save rewrote a read-only cache");
    curlx_fclose(fp);
    fail_unless(!Curl_hsts_save(writer, writer->hsts, savename),
                "writable shared HSTS save");
    fp = curlx_fopen(savename, "rb");
    abort_unless(fp, "could not read writable HSTS cache");
    fail_unless(fgetc(fp) == '#', "writable shared handle did not save");
    curlx_fclose(fp);
    fail_unless(!curl_easy_setopt(writer, CURLOPT_HSTS_CTRL,
                                  CURLHSTS_ENABLE | CURLHSTS_READONLYFILE),
                "set read-only policy after sharing");
    fail_unless(writer->set.hsts_readonly,
                "late read-only policy was not retained");
    curl_easy_reset(writer);
    fail_unless(!writer->set.hsts_readonly && clone->set.hsts_readonly,
                "reset did not restore only this handle's default policy");
    unlink(savename);
  }
  curl_easy_cleanup(writer);
  curl_easy_cleanup(clone);
  curl_share_cleanup(share);
  result = curl_easy_setopt(easy, CURLOPT_HSTS_CTRL, CURLHSTS_ENABLE);
  fail_unless(!result && !easy->set.hsts_readonly,
              "could not restore writable HSTS policy");

  Curl_hsts_loadfile(easy, h, arg);

  for(i = 0; headers[i].host; i++) {
    if(headers[i].hdr) {
      result = Curl_hsts_parse(h, headers[i].host, headers[i].hdr);

      if(result != headers[i].result) {
        curl_mfprintf(stderr, "Curl_hsts_parse(%s) failed: %d\n",
                      headers[i].hdr, (int)result);
        unitfail++;
        continue;
      }
      else if(result) {
        curl_mprintf("Input %d: error %d\n", i, (int)result);
        continue;
      }
    }

    chost = headers[i].chost ? headers[i].chost : headers[i].host;
    e = hsts_check(h, chost, strlen(chost), TRUE);
    showsts(e, chost);
  }

  result = Curl_hsts_parse(h, "prefix.example",
                           "max-age=60; includeSubDomainsExtra");
  fail_if(result, "failed to parse unknown HSTS directive");
  e = hsts_check(h, "child.prefix.example",
                 strlen("child.prefix.example"), TRUE);
  fail_if(e, "unknown directive enabled subdomain matching");
  result = Curl_hsts_parse(h, "prefix.example", "max-age=0");
  fail_if(result, "failed to remove HSTS test entry");

  result = Curl_hsts_parse(h, "unknown.example",
                           "max-age-extra=1; max-age=60");
  fail_if(result, "failed to ignore unknown HSTS directive");
  e = hsts_check(h, "unknown.example", strlen("unknown.example"), FALSE);
  fail_if(!e, "recognized directive after unknown directive was ignored");
  result = Curl_hsts_parse(h, "unknown.example", "max-age=0");
  fail_if(result, "failed to remove HSTS test entry");

  curl_mprintf("Number of entries: %zu\n", Curl_llist_count(&h->list));

  /* verify that it is exists for 7 seconds */
  chost = "expire.example";
  for(i = 100; i < 110; i++) {
    e = hsts_check(h, chost, strlen(chost), TRUE);
    showsts(e, chost);
    deltatime++; /* another second passed */
  }

  curl_msnprintf(savename, sizeof(savename), "%s.save", arg);
  (void)Curl_hsts_save(easy, h, savename);
  Curl_hsts_cleanup(&h);
  curl_easy_cleanup(easy);
  curl_global_cleanup();

  UNITTEST_END(curl_global_cleanup())
}
#else
static CURLcode test_unit1660(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("nothing to do when HTTP or HSTS are disabled");
  UNITTEST_END_SIMPLE
}
#endif
