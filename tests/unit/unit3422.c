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
#include "multi_ntfy.h"

struct ntfy_state {
  struct Curl_easy *first;
  struct Curl_easy *victim;
  struct Curl_easy *replacement;
  unsigned int calls;
};

static void ntfy_cb(CURLM *multi, unsigned int type, CURL *easy,
                     void *userdata)
{
  struct ntfy_state *state = userdata;
  state->calls++;
  fail_unless(type == CURLMNOTIFY_EASY_DONE, "unexpected notification");
  if(easy == state->first) {
    uint32_t oldmid = state->victim->mid;
    fail_unless(curl_multi_remove_handle(multi, state->victim) == CURLM_OK,
                "could not remove completed handle");
    fail_unless(curl_multi_add_handle(multi, state->replacement) == CURLM_OK,
                "could not add replacement");
    fail_unless(state->replacement->mid == oldmid,
                "test must reuse the removed transfer ID");
  }
  else
    fail_unless(easy == state->replacement, "unexpected handle");
}

static CURLcode test_unit3422(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  struct Curl_multi *multi;
  struct ntfy_state state;
  struct Curl_easy *scratch;
  uint32_t i, capacity;

  memset(&state, 0, sizeof(state));
  abort_unless(!curl_global_init(CURL_GLOBAL_ALL), "global init");
  multi = curl_multi_init();
  abort_unless(multi, "multi init");
  state.first = curl_easy_init();
  state.victim = curl_easy_init();
  state.replacement = curl_easy_init();
  abort_unless(state.first && state.victim && state.replacement, "easy init");
  fail_unless(!curl_multi_add_handle(multi, state.first), "add first");
  fail_unless(!curl_multi_add_handle(multi, state.victim), "add victim");
  scratch = curl_easy_init();
  abort_unless(scratch, "scratch init");
  fail_unless(!curl_multi_add_handle(multi, scratch), "add scratch");
  capacity = Curl_uint32_tbl_capacity(&multi->xfers);
  /* Advance the round-robin allocator to its wrap point without growing
     the table. The next freed slot will then be reused immediately. */
  for(i = scratch->mid; i < capacity - 1; ++i) {
    fail_unless(!curl_multi_remove_handle(multi, scratch), "remove scratch");
    fail_unless(!curl_multi_add_handle(multi, scratch), "re-add scratch");
  }
  curl_multi_setopt(multi, CURLMOPT_NOTIFYFUNCTION, ntfy_cb);
  curl_multi_setopt(multi, CURLMOPT_NOTIFYDATA, &state);
  curl_multi_notify_enable(multi, CURLMNOTIFY_EASY_DONE);
  Curl_mntfy_add(state.first, CURLMNOTIFY_EASY_DONE);
  Curl_mntfy_add(state.victim, CURLMNOTIFY_EASY_DONE);
  fail_unless(!Curl_mntfy_dispatch_all(multi), "dispatch");
  fail_unless(state.calls == 1, "removed handle event reached replacement");
  Curl_mntfy_add(state.replacement, CURLMNOTIFY_EASY_DONE);
  fail_unless(!Curl_mntfy_dispatch_all(multi), "replacement dispatch");
  fail_unless(state.calls == 2, "replacement's own event was lost");
  curl_multi_remove_handle(multi, scratch);
  curl_easy_cleanup(scratch);
  curl_multi_remove_handle(multi, state.first);
  curl_multi_remove_handle(multi, state.replacement);
  curl_easy_cleanup(state.first);
  curl_easy_cleanup(state.victim);
  curl_easy_cleanup(state.replacement);
  curl_multi_cleanup(multi);
  curl_global_cleanup();
  UNITTEST_END_SIMPLE
}
