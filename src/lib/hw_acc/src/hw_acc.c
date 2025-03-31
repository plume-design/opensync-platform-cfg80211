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

/*
 * cfg80211 hw acc utilities
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "hw_acc.h"
#include "os.h"
#include "log.h"
#include "os_util.h"
#include "kconfig.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

bool hw_acc_flush(struct hw_acc_flush_flow_t *flow)
{
    LOGE("hw_acc: hw_acc_flush N/A");
    return true;
}

bool hw_acc_flush_flow_per_device(int devid)
{
    LOGE("hw_acc: hw_acc_flush_flow_per_device N/A");
    return true;
}

bool hw_acc_flush_flow_per_mac(const char *mac)
{
#if defined(CONFIG_PLATFORM_IS_MTK)
#if defined(CONFIG_MTK_HW_ACC_HNAT)
/**
 * For platforms using HNAT (like MTK's Jaguar)
 * Usage: echo [type] [option] > /sys/kernel/debug/hnat/hnat_entry
 * Commands:   [type] [option]
 *               8   <mac>        Delete all PPEs foe entry of assinged smac and dmac
 */
    char cmd[32] = {0};

    snprintf(cmd, sizeof(cmd), "8 %s\n", mac);
    if (file_put(CONFIG_MTK_HW_ACC_HNAT_FLUSH_PATH, cmd) == -1)
    {
        LOGW("hw_acc: hw_acc_flush_flow_per_mac for %s failed", mac);
        return false;
    }
#endif //CONFIG_MTK_HW_ACC_HNAT

#if defined(CONFIG_MTK_HW_ACC_FILE_PATH)
/**
 * For platforms like MTK's Panther
 */

    if (file_put(CONFIG_MTK_HW_ACC_FILE_PATH, mac) == -1)
    {
        return false;
    }
#endif //CONFIG_MTK_HW_ACC_FILE_PATH
    LOGD("hw_acc: flushed mac '%s'", mac);

#endif //CONFIG_PLATFORM_IS_MTK
    return true;
}

bool hw_acc_flush_all_flows(void)
{
#if defined(CONFIG_PLATFORM_IS_MTK) && defined(CONFIG_MTK_HW_ACC_HNAT)
/**
 * For platforms using HNAT (like MTK's Jaguar)
 * Usage: echo [type] [option] > /sys/kernel/debug/hnat/hnat_entry
 * Commands:   [type] [option]
 *               3   <entry_idx>  Delete PPE0 specific foe entry of assigned <entry_idx>
 *               5   <entry_idx>  Delete PPE1 specific foe entry of assigned <entry_idx>
 *               7   <entry_idx>  Delete PPE2 specific foe entry of assigned <entry_idx>
 *                                When entry_idx is -1, clear all entries
 */
    int i;
    bool rc = true;
    char cmd[32] = {0};

    for (i=3; i<=7; i+=2)
    {
        snprintf(cmd, sizeof(cmd), "%d -1\n", i);
        if (file_put(CONFIG_MTK_HW_ACC_HNAT_FLUSH_PATH, cmd) == -1)
        {
            LOGW("hw_acc: hw_acc_flush_all_flows for foe: %d failed", i);
            rc = false;
        }

        memset(cmd, 0, sizeof(cmd));
    }

    LOGD("hw_acc: flushed all");
    return rc;

#endif //CONFIG_PLATFORM_IS_MTK && CONFIG_MTK_HW_ACC_HNAT

    return true;
}

void hw_acc_enable()
{
#if defined(CONFIG_PLATFORM_IS_MTK) && defined(CONFIG_MTK_HW_ACC_HNAT)
    if (file_put(CONFIG_MTK_HW_ACC_HNAT_ENABLE_PATH, "1\n") == -1)
    {
        LOGW("hw_acc: hw_acc_enable failed");
    }
#endif //CONFIG_PLATFORM_IS_MTK && CONFIG_MTK_HW_ACC_HNAT

    return;
}

void hw_acc_disable()
{
#if defined(CONFIG_PLATFORM_IS_MTK) && defined(CONFIG_MTK_HW_ACC_HNAT)
    if (file_put(CONFIG_MTK_HW_ACC_HNAT_ENABLE_PATH, "0\n") == -1)
    {
        LOGW("hw_acc: hw_acc_disable failed");
    }
#endif //CONFIG_PLATFORM_IS_MTK && CONFIG_MTK_HW_ACC_HNAT

    return;
}
