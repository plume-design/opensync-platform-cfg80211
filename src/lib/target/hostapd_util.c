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

#include "os.h"
#include "log.h"
#include "hostapd_util.h"
#include "dpp_types.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

bool hostapd_client_disconnect(const char *vif, const char *disc_type, const char *mac_str, uint8_t reason)
{
    char hostapd_cmd[512];
    bool ret = false;
    char phy[32];

    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
             "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s %s %s reason=%hhu",
             HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif, disc_type, mac_str, reason);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_btm_request(const char *vif, const char *btm_req_cmd)
{
    char    hostapd_cmd[1024];
    bool    ret = false;
    char    phy[32];

    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s bss_tm_req %s",
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif, btm_req_cmd);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_rrm_beacon_report_request(const char *vif,
                                       const char *mac_addr,
                                       const char *req_hex_buf)
{
    char    hostapd_cmd[1024];
    bool    ret = false;
    char    phy[32];

    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s "
            "req_beacon %s %s",
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif, mac_addr, req_hex_buf);

    ret = !cmd_log(hostapd_cmd);
    if (!ret)
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);

    return ret;
}

bool hostapd_rrm_set_neighbor(const char *vif, const char *bssid, const char *hex_ssid, const char *nr)
{
    char    hostapd_cmd[1024];
    bool    ret = false;
    char    phy[32];

    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s "
            "set_neighbor %s ssid=%s nr=%s",
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif, bssid, hex_ssid, nr);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_rrm_remove_neighbor(const char *vif, const char *bssid)
{
    char    hostapd_cmd[1024];
    bool    ret = false;
    char    phy[32];

    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s "
            "remove_neighbor %s ",
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif, bssid);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_acl_update(const char *vif, const uint8_t *mac_addr, int add)
{
    char hostapd_cmd[1024];
    bool ret = true;
    bool status;
    char phy[32];

    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s "
            "DENY_ACL %s "MAC_ADDRESS_FORMAT,
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif,
            add ? "DEL_MAC" : "ADD_MAC", MAC_ADDRESS_PRINT(mac_addr));

    status = !cmd_log(hostapd_cmd);
    if (!status) {
        ret = false;
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}
