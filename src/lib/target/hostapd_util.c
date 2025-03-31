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
#include <stdlib.h>

#include "os.h"
#include "log.h"
#include "dpp_types.h"
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"

#include "hostapd_util.h"
#include "target_util.h"
#include "nl80211.h"
#include "wiphy_info.h"
#include "target_cfg80211.h"
#include "util.h"


#define MODULE_ID LOG_MODULE_ID_TARGET

#define CHAN_SWITCH_DEFAULT_CS_COUNT 15

#define for_each_mac(mac, list) \
    for (mac = strtok(list, " \t\n"); mac; mac = strtok(NULL, " \t\n"))

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

    ret = !cmd_log_check_safe(hostapd_cmd);
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

    ret = !cmd_log_check_safe(hostapd_cmd);
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

    ret = !cmd_log_check_safe(hostapd_cmd);
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

    ret = !cmd_log_check_safe(hostapd_cmd);
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

    ret = !cmd_log_check_safe(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

#ifdef CONFIG_PLATFORM_IS_MTK
bool hostapd_deny_acl_update(const char *vif, const uint8_t *mac_addr, int add, int disconnect)
#else
bool hostapd_deny_acl_update(const char *vif, const uint8_t *mac_addr, int add)
#endif
{
    char hostapd_cmd[1024];
    bool ret = true;
    bool status;
    char phy[32];

    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return false;

#ifdef CONFIG_PLATFORM_IS_MTK
    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s "
            "DENY_ACL %s "MAC_ADDRESS_FORMAT,
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif,
            add ? (disconnect ? "ADD_MAC" : "BAK_MAC") : "DEL_MAC", MAC_ADDRESS_PRINT(mac_addr));
#else
    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s "
            "DENY_ACL %s "MAC_ADDRESS_FORMAT,
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif,
            add ? "ADD_MAC" : "DEL_MAC", MAC_ADDRESS_PRINT(mac_addr));
#endif

    status = !cmd_log_check_safe(hostapd_cmd);
    if (!status) {
        ret = false;
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

int hostapd_mac_acl_clear(const char *phy, const char *vif)
{
    char hostapd_cmd[1024];
    bool status;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
        "timeout -s KILL 3 hostapd_cli -p %s/hostapd-%s -i %s "
        "ACCEPT_ACL CLEAR",
        HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif);

    status = !cmd_log_check_safe(hostapd_cmd);
    if (!status)
        LOGI("hostapd_cli execution failed: %s", hostapd_cmd);

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
        "timeout -s KILL 3 hostapd_cli -p %s/hostapd-%s -i %s "
        "DENY_ACL CLEAR",
        HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif);

    status = !cmd_log_check_safe(hostapd_cmd);
    if (!status)
        LOGI("hostapd_cli execution failed: %s", hostapd_cmd);

    return 0;
}

bool hostapd_mac_acl_accept_add(const char *phy, const char *vif, const char *mac_list_buf)
{
    char hostapd_cmd[1024];
    bool ret = true;
    bool status;
    char *mac;
    char *p;

    hostapd_mac_acl_clear(phy, vif);

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
        "timeout -s KILL 3 hostapd_cli -p %s/hostapd-%s -i %s "
        "SET macaddr_acl 1",
         HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif);

    status = !cmd_log_check_safe(hostapd_cmd);
    if (!status) {
        LOGI("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    for_each_mac(mac, (p = strdup(mac_list_buf))) {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 3 hostapd_cli -p %s/hostapd-%s -i %s "
            "ACCEPT_ACL ADD_MAC %s",
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif, mac);

        status = !cmd_log_check_safe(hostapd_cmd);
        if (!status) {
            ret = false;
            LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
        }
    }

    free(p);

    return ret;
}

bool hostapd_mac_acl_deny_add(const char *phy, const char *vif, const char *mac_list_buf)
{
    char hostapd_cmd[1024];
    bool ret = true;
    bool status;
    char *mac;
    char *p;

    hostapd_mac_acl_clear(phy, vif);

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
        "timeout -s KILL 3 hostapd_cli -p %s/hostapd-%s -i %s "
        "SET macaddr_acl 0",
         HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif);

    status = !cmd_log_check_safe(hostapd_cmd);
    if (!status) {
        LOGI("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    for_each_mac(mac, (p = strdup(mac_list_buf))) {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 3 hostapd_cli -p %s/hostapd-%s -i %s "
            "DENY_ACL ADD_MAC %s",
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif, mac);

        status = !cmd_log_check_safe(hostapd_cmd);
        if (!status) {
            ret = false;
            LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
        }
    }

    free(p);

    return ret;
}

bool hostapd_get_mac_acl_info(const char *phy,
                         const char *vif,
                         struct schema_Wifi_VIF_State *vstate)
{
    char *accept_buf = NULL;
    char *deny_buf = NULL;
    char *buf = NULL;
    char sockdir[64];
    char *line;
    char *mac_addr;

    if (strstr(vif, "sta"))
        return false;

    snprintf(sockdir, sizeof(sockdir), "%s/hostapd-%s", HOSTAPD_CONTROL_PATH_DEFAULT, phy);

    accept_buf = HOSTAPD_CLI(sockdir, vif, "ACCEPT_ACL", "SHOW");

    deny_buf = HOSTAPD_CLI(sockdir, vif, "DENY_ACL", "SHOW");

    if ((deny_buf && (strlen(deny_buf) > 0)) && (!accept_buf || !strlen(accept_buf)))
        STRSCPY(vstate->mac_list_type, "blacklist");
    else if ((accept_buf && (strlen(accept_buf)) > 0) && (!deny_buf || !strlen(deny_buf)))
        STRSCPY(vstate->mac_list_type, "whitelist");
    else
        return false;

    if (strlen(deny_buf) > 0)
        buf = strdupa(deny_buf);
    else
        buf = strdupa(accept_buf);

    while ((line = strsep(&buf, "\n")) != NULL) {
        if ((mac_addr = strsep(&line, " ")) != NULL) {
            if (strlen(mac_addr) > 0) {
                if ((unsigned long) vstate->mac_list_len < ARRAY_SIZE(vstate->mac_list)) {
                    STRSCPY(vstate->mac_list[vstate->mac_list_len], mac_addr);
                    vstate->mac_list_len++;
                } else {
                    LOGW("ACL rule entries over the size of mac_list, skip MAC %s", mac_addr);
                }
            }
        }
    }
    return true;
}

bool hostapd_set_bcn_int(const char *phy, const char *vif, const int bcn_int)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s "
            "set beacon_int %d",
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif, bcn_int);

    ret = !cmd_log_check_safe(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_vif_reload(const char *phy, const char *vif)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 5 hostapd_cli -p %s/hostapd-%s -i %s reload",
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif);

    ret = !cmd_log_check_safe(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_get_vif_status(const char *vif, const char *key, char value[BFR_SIZE_64])
{
    char phy[BFR_SIZE_64];
    char sockdir[BFR_SIZE_64] = "";
    char buf[256];
    char *bss_status;
    const char *k;
    const char *v;
    char *kv;

    if (util_get_vif_radio(vif, phy, sizeof(phy))) {
        LOGD("%s: failed to get ap vif radio", vif);
        return false;
    }

    util_get_opmode(vif, buf, sizeof(buf));

    if (!strcmp(buf, "ap"))
        snprintf(sockdir, sizeof(sockdir), "%s/hostapd-%s", HOSTAPD_CONTROL_PATH_DEFAULT, phy);
    else if (!strcmp(buf, "sta"))
        snprintf(sockdir, sizeof(sockdir), "%s/wpa_supplicant-%s", HOSTAPD_CONTROL_PATH_DEFAULT, phy);
    else
        return false;

    bss_status = HOSTAPD_CLI(sockdir, vif, "STATUS");
    if (!bss_status || (!strlen(bss_status))) {
        LOGD("%s: failed to get vif status", vif);
        return false;
    }

    while ((kv = strsep(&bss_status, "\r\n"))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, key)) {
                strscpy(value, v, BFR_SIZE_64);
                LOGI("%s: get %s=%s from hostapd status", vif, key, value);
                return true;
            }
        }
    }
    return false;
}

int hostapd_chan_switch(const char *phy,
                        const char *vif,
                        int channel,
                        char *center_freq1_str,
                        char *sec_chan_offset_str,
                        char *punct_bitmap_str,
                        char *opt_chan_info)
{
    char hostapd_cmd[1024] = "";
    bool status;
    const struct wiphy_info *wiphy_info;
    int freq;
    bool is_6g;

    freq = 0;
    is_6g = false;
    wiphy_info = wiphy_info_get(phy);
    if (wiphy_info && !strcmp(wiphy_info->band, "6G"))
        is_6g = true;
    if (!is_6g)
        freq = util_chan_to_freq(channel);
    else
        freq = util_chan_to_freq_6g(channel);

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "timeout -s KILL 3 hostapd_cli -p %s/hostapd-%s -i %s CHAN_SWITCH %d %d %s %s %s %s",
            HOSTAPD_CONTROL_PATH_DEFAULT, phy, vif,
            CHAN_SWITCH_DEFAULT_CS_COUNT,
            freq,
            strlen(center_freq1_str) ? center_freq1_str : "",
            strlen(sec_chan_offset_str) ? sec_chan_offset_str : "",
            strlen(punct_bitmap_str) ? punct_bitmap_str : "",
            strlen(opt_chan_info) ? opt_chan_info : "");

    LOGI("%s: %s", __func__, hostapd_cmd);

    status = !cmd_log_check_safe(hostapd_cmd);
    if (!status) {
        LOGI("hostapd_cli execution failed: %s", hostapd_cmd);
        return -1;
    }

    return 0;
}

static void util_hex_to_bytes(const char *hex, uint8_t *bytes, int length)
{
    if (!bytes)
        return;

    const char *pos = hex;
    for (int i = 0; i < length ; i++) {
        sscanf(pos, "%2hhx", &bytes[i]);
        pos += 2;
    }
}

bool hostapd_sta_info(const char *vif, const char *mac, hostapd_sta_info_t *sta)
{
    char sockdir[64] = "";
    char *sta_info = NULL;
    const char *k;
    const char *v;
    const char *vht_caps_info = "";
    const char *rx_vht_mcs_map = "";
    const char *tx_vht_mcs_map = "";
    const char *ht_mcs_bitmask = "";
    const char *ht_caps_info = "";
    char *kv;

    const char *he_mac_capab_info = "";
    const char *he_phy_capab_info = "";
    const char *he_capab_optional = "";
    const char *he_capab_len = "";

    char phy[32] = {'\0'};
    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return false;
    if (!sta)
        return false;

    snprintf(sockdir, sizeof(sockdir), "%s/hostapd-%s", HOSTAPD_CONTROL_PATH_DEFAULT, phy);

    sta_info = HOSTAPD_CLI(sockdir, vif, "sta", mac);
    if (!sta_info || (!strlen(sta_info)))
        return false;

    while ((kv = strsep(&sta_info, "\r\n"))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "vht_caps_info"))
                vht_caps_info = v;
            if (!strcmp(k, "rx_vht_mcs_map"))
                rx_vht_mcs_map = v;
            if (!strcmp(k, "tx_vht_mcs_map"))
                tx_vht_mcs_map = v;
            if (!strcmp(k, "ht_caps_info"))
                ht_caps_info = v;
            if (!strcmp(k, "ht_mcs_bitmask"))
                ht_mcs_bitmask = v;
            /*
               Below keys are not standard output of hostapd,
               we have to apply a custom patch so that hostapd can
               expose these parameters in raw data
               (without converting to little endian)...
            */
            if (!strcmp(k, "he_capab_len"))
                he_capab_len = v;
            if (!strcmp(k, "he_mac_capab_info"))
                he_mac_capab_info = v;
            if (!strcmp(k, "he_phy_capab_info"))
                he_phy_capab_info = v;
            if (!strcmp(k, "he_capab_optional"))
                he_capab_optional = v;
        }
    }
    LOGD("%s: vht_caps_info[%s], rx_vht_mcs_map[%s], tx_vht_mcs_map=[%s]"
            "\nht_caps_info[%s], ht_mcs_bitmask=[%s]"
            "\nhe_capab_len[%s], he_mac_capab_info[%s], he_phy_capab_info=[%s]"
            ,
         __func__, vht_caps_info, rx_vht_mcs_map, tx_vht_mcs_map,
                ht_caps_info, ht_mcs_bitmask,
                he_capab_len, he_mac_capab_info, he_phy_capab_info);

    if (strlen(vht_caps_info))
        sta->vht_caps_info = (uint32_t) strtoul(vht_caps_info, NULL, 16);
    if (strlen(rx_vht_mcs_map))
        sta->vht_rx_mcs_map = (uint16_t) strtoul(rx_vht_mcs_map, NULL, 16);
    if (strlen(tx_vht_mcs_map))
        sta->vht_tx_mcs_map = (uint16_t) strtoul(tx_vht_mcs_map, NULL, 16);
    if (strlen(ht_caps_info))
        sta->ht_caps_info = (uint16_t) strtoul(ht_caps_info, NULL, 16);
    if (strlen(ht_mcs_bitmask))
        util_hex_to_bytes(ht_mcs_bitmask, sta->ht_mcs_set, HT_CAP_MCS_BITMASK_LEN);
    if (strlen(he_capab_len)) {
        sta->he_capab_len = (uint16_t) atoi(he_capab_len);
        if (strlen(he_mac_capab_info))
            util_hex_to_bytes(he_mac_capab_info, sta->he_mac_capab_info, HE_CAP_MAC_INFO_LEN);
        if (strlen(he_phy_capab_info))
            util_hex_to_bytes(he_phy_capab_info, sta->he_phy_capab_info, HE_CAP_PHY_INFO_LEN);
        if (strlen(he_capab_optional))
            util_hex_to_bytes(he_capab_optional, sta->he_capab_optional,
                sta->he_capab_len - HE_CAP_MIN_LEN);
    }
    return true;
}
