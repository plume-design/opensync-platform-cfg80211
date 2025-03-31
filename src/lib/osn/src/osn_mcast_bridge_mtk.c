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

#include <net/if.h>

#include "log.h"
#include "execsh.h"
#include "os_util.h"
#include "kconfig.h"

#include "osn_mcast_mtk.h"

/* Default number of apply retries before giving up */
#define MCPD_APPLY_RETRIES  5

void osn_mcast_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent);

/* Bridge igmp snooping config */
static char set_mcast_snooping_bridge[] = _S(echo "$1" > /sys/devices/virtual/net/"$2"/bridge/multicast_snooping);

osn_mcast_bridge osn_mcast_bridge_base;

static osn_mcast_bridge *osn_mcast_bridge_init()
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;

    if (self->initialized)
        return self;

    /* Initialize apply debounce */
    ev_debounce_init2(&self->apply_debounce, osn_mcast_apply_fn, 0.4, 2.0);

    self->initialized = true;

    return self;
}

osn_igmp_t *osn_mcast_bridge_igmp_init()
{
    osn_mcast_bridge *self = osn_mcast_bridge_init();
    self->igmp_initialized = true;

    return &self->igmp;
}

osn_mld_t *osn_mcast_bridge_mld_init()
{
    osn_mcast_bridge *self = osn_mcast_bridge_init();
    self->mld_initialized = true;

    return &self->mld;
}

char *osn_mcast_other_config_get_string(
        const struct osn_mcast_other_config *other_config,
        const char *key)
{
    int ii;

    for (ii = 0; ii < other_config->oc_len; ii++)
    {
        if (strcmp(other_config->oc_config[ii].ov_key, key) == 0)
        {
            return other_config->oc_config[ii].ov_value;
        }
    }

    return NULL;
}

long osn_mcast_other_config_get_long(const struct osn_mcast_other_config *other_config, const char *key)
{
    char *str = osn_mcast_other_config_get_string(other_config, key);
    long val;

    if (str == NULL && os_strtoul(str, &val, 0) == true)
    {
        return val;
    }

    return 0;
}

bool osn_mcast_free_string_array(char **arr, int len) {
    int ii;

    for (ii = 0; ii < len; ii++)
    {
        FREE(arr[ii]);
    }
    FREE(arr);

    return true;
}

static bool osn_mcast_bridge_deconfigure(osn_mcast_bridge *self)
{
    int status;

    if (self->snooping_bridge[0] == '\0')
        return true;

    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_snooping_bridge, "0", self->snooping_bridge);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_bridge_deconfigure: Cannot disable snooping on bridge %s",
                self->snooping_bridge);
    }

    self->snooping_bridge[0] = '\0';
    return true;
}

bool osn_mcast_apply()
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;
    self->apply_retry = MCPD_APPLY_RETRIES;
    ev_debounce_start(EV_DEFAULT, &self->apply_debounce);

    return true;
}

bool osn_mcast_apply_bridge_config(osn_mcast_bridge *self)
{
    osn_igmp_t *igmp = &self->igmp;
    osn_mld_t *mld = &self->mld;
    bool snooping_enabled;
    char *snooping_bridge;
    bool snooping_bridge_up;
    int status;

    LOG(DEBUG, "osn_mcast_apply_bridge_config");

    if (igmp->snooping_enabled || !mld->snooping_enabled)
    {
        snooping_enabled = igmp->snooping_enabled;
        snooping_bridge = igmp->snooping_bridge;
        snooping_bridge_up = igmp->snooping_bridge_up;
    }
    else
    {
        snooping_enabled = mld->snooping_enabled;
        snooping_bridge = mld->snooping_bridge;
        snooping_bridge_up = mld->snooping_bridge_up;
    }

    /* If snooping was turned off or snooping bridge was changed, deconfigure it first */
    if (snooping_bridge_up == false || strncmp(self->snooping_bridge, snooping_bridge, IFNAMSIZ) != 0)
        osn_mcast_bridge_deconfigure(self);

    if (snooping_bridge_up == false || snooping_bridge[0] == '\0')
        return true;

    /* Enable/disable snooping */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_snooping_bridge, snooping_enabled ? "1" : "0",
                        snooping_bridge);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_apply_bridge_config: Cannot disable snooping on bridge %s",
                self->snooping_bridge);
        return true;
    }
    STRSCPY_WARN(self->snooping_bridge, snooping_bridge);

    return true;
}

void osn_mcast_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent)
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;
    bool status;

    status = osn_mcast_apply_bridge_config(self);

    if (!self->igmp_initialized && !self->mld_initialized)
        return;

    /* Apply mcast bridge configuration */
    if (status == false)
    {
        /* Schedule retry until retry limit reached */
        if (self->apply_retry > 0)
        {
            LOG(INFO, "osn_mcast_apply_fn: retry %d", self->apply_retry);
            self->apply_retry--;
            ev_debounce_start(loop, w);
            return;
        }

        LOG(ERR, "osn_mcast_apply_fn: Unable to apply mcast bridge configuration.");
    }

    return;
}

bool os_is_mcproxy_available(void)
{
    if (access("/usr/sbin/mcproxy", F_OK) != 0)
        return false;

    return true;
}
