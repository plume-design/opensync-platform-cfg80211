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

#include <ev.h>                 // libev routines
#include <getopt.h>             // command line arguments

#include "log.h"                // logging routines
#include "target.h"             // target API

#include "target_nl80211.h"    // module header

static log_severity_t  log_severity = LOG_SEVERITY_INFO;

#define MODULE_ID LOG_MODULE_ID_MAIN

int main(int argc, char ** argv)
{
    struct ev_loop *loop = EV_DEFAULT;

    if (os_get_opt(argc, argv, &log_severity))
    {
        return -1;
    }

    target_log_open("OPENSYNC_CFG80211", 0);
    LOGN("Initializing OPENSYNC_CFG80211");
    log_severity_set(log_severity);
    log_register_dynamic_severity(loop);

    backtrace_init();

    json_memdbg_init(loop);

    // TODO: Fix - Initialize target structure
    if (!target_init(TARGET_INIT_MGR_HELLO_WORLD, loop))
    {
        LOGE("Initializing HELLO NL80211 "
             "(Failed to initialize target library)");
        return -1;
    }

    target_nl80211_init(loop);

    ev_run(loop, 0);

    target_close(TARGET_INIT_MGR_HELLO_WORLD, loop);

    ev_loop_destroy(loop);

    LOGN("Exiting OPENSYNC_CFG80211");

    return 0;
}
