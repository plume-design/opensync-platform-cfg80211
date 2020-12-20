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
#include <stdio.h>
#include <stdbool.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include "target.h"
#include "log.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "util.h"

#include <linux/un.h>

#include "mcproxy_util.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

bool target_set_igmp_mcproxy_params(target_mcproxy_params_t *mcparams)
{
    // Initialize the daemons (if already initialized then this is a no-op)
    mcproxy_util_daemon_init(mcparams->protocol);

    // Apply the config and restart the proxy
    if (mcproxy_util_apply(mcparams) == false)
        return false;

    return true;
}

bool target_set_igmp_mcproxy_sys_params(struct schema_IGMP_Config *iccfg)
{
    if (WARN_ON(mcproxy_util_update_igmp_sys_params(iccfg) == false))
        return false;

    return true;
}

bool target_set_mld_mcproxy_params(target_mcproxy_params_t *mcparams)
{
    // Initialize the daemons (if already initialized then this is a no-op)
    mcproxy_util_daemon_init(mcparams->protocol);

    // Apply the config and restart the proxy
    if (mcproxy_util_apply(mcparams) == false)
        return false;

    return true;
}

bool target_set_mld_mcproxy_sys_params(struct schema_MLD_Config *mlcfg)
{
    if (WARN_ON(mcproxy_util_update_mld_sys_params(mlcfg) == false))
        return false;

    return true;
}
