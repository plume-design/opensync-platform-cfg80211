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

#define MODULE_ID LOG_MODULE_ID_TARGET


/******************************************************************************
 *  TARGET definitions
 *****************************************************************************/

struct ev_loop *target_mainloop;

bool target_init(target_init_opt_t opt, struct ev_loop *loop)
{
    target_mainloop = loop;
    if (opt == TARGET_INIT_MGR_SM) {
        if (nl_sm_init(loop) < 0) {
            LOGE("%s: Initializing SM (Failed to init)",__func__);
            return false;
        }
        LOGI("%s: sm event loop initialized", __func__);
    }
    return true;
}
