/*
Copyright (c) 2020, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>

#include "target.h"
#include "nl80211.h"
#include "target_cfg80211.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

static ev_signal        _ev_sigterm;
static ev_signal        _ev_sigkill;
static ev_signal        _ev_sigint;
static ev_signal        _ev_sigsegv;

/******************************************************************************
 *  TARGET definitions
 *****************************************************************************/
struct ev_loop *target_mainloop;

static void
handle_signal(struct ev_loop *loop, ev_signal *w, int revents)
{
    LOGEM("Received signal %d, triggering shutdown", w->signum);
    ev_break(loop, EVBREAK_ALL);
    return;
}

static void
reg_signal_handlers(struct ev_loop *loop)
{
    ev_signal_init(&_ev_sigterm, handle_signal, SIGTERM);
    ev_signal_start(loop, &_ev_sigterm);
    ev_signal_init(&_ev_sigkill, handle_signal, SIGKILL);
    ev_signal_start(loop, &_ev_sigkill);
    ev_signal_init(&_ev_sigint, handle_signal, SIGINT);
    ev_signal_start(loop, &_ev_sigint);
    ev_signal_init(&_ev_sigsegv, handle_signal, SIGSEGV);
    ev_signal_start(loop, &_ev_sigsegv);
}

bool target_init(target_init_opt_t opt, struct ev_loop *loop)
{
    if (opt == TARGET_INIT_MGR_SM) {
        if (nl_sm_init(loop) < 0) {
            LOGE("%s: Initializing SM (Failed to init)",__func__);
            return false;
        }
        reg_signal_handlers(loop);
        LOGI("%s: sm event loop initialized", __func__);
    } else if (opt == TARGET_INIT_MGR_WM) {
        target_mainloop = loop;
        reg_signal_handlers(loop);
    }
    return true;
}

bool target_close(target_init_opt_t opt, struct ev_loop *loop)
{
    if (opt == TARGET_INIT_MGR_WM)
        nl_wm_deinit();
    else if (TARGET_INIT_MGR_SM)
        nl_sm_deinit();

    return true;
}
