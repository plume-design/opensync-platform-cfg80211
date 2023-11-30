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
#ifndef HOSTAPD_UTIL_H_INCLUDED
#define HOSTAPD_UTIL_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "kconfig.h"

#define HOSTAPD_CONTROL_PATH_DEFAULT "/var/run"
#define EXEC(...) strexa(__VA_ARGS__)
#define CMD_TIMEOUT(...) "timeout", "-s", "KILL", "3", ## __VA_ARGS__
#define HOSTAPD_CLI(sockdir, vif, ...) EXEC(CMD_TIMEOUT("hostapd_cli", "-p", sockdir, "-i", vif, ## __VA_ARGS__))

#define SSID_MAX_LEN 32
#define MAC_STR_LEN (12 + 5 + 1)

#define VHT_CAP_MCS_MAP_NSS_MAX 8
#define HT_CAP_MCS_SET_LEN 16
#define HT_CAP_MCS_BITMASK_LEN 10

#define HE_CAP_MAC_INFO_LEN     6
#define HE_CAP_PHY_INFO_LEN     11
#define HE_CAP_MIN_LEN          (HE_CAP_MAC_INFO_LEN + HE_CAP_PHY_INFO_LEN)
#define HE_CAP_OPT_MAX_LEN      37

typedef struct
{
    uint32_t vht_caps_info;
    uint16_t vht_tx_mcs_map;
    uint16_t vht_rx_mcs_map;
    uint16_t ht_caps_info;
    uint8_t ht_mcs_set[HT_CAP_MCS_SET_LEN];
    uint16_t he_capab_len;
    uint8_t he_mac_capab_info[HE_CAP_MAC_INFO_LEN];
    uint8_t he_phy_capab_info[HE_CAP_PHY_INFO_LEN];
    uint8_t he_capab_optional[HE_CAP_OPT_MAX_LEN];
} hostapd_sta_info_t;

bool hostapd_client_disconnect(const char *interface, const char *disc_type,
                               const char *mac_str, uint8_t reason);
bool hostapd_btm_request(const char *interface, const char *btm_req_cmd);

bool hostapd_rrm_set_neighbor(const char *interface, const char *bssid, const char *hex_ssid, const char *nr);

bool hostapd_rrm_remove_neighbor(const char *interface, const char *bssid);

#ifdef CONFIG_PLATFORM_IS_MTK
bool hostapd_deny_acl_update(const char *vif, const uint8_t *mac_addr, int add, int disconnect);
#else
bool hostapd_deny_acl_update(const char *vif, const uint8_t *mac_addr, int add);
#endif
bool hostapd_rrm_beacon_report_request(
        const char *vif,
        const char *mac_addr,
        const char *req_hex_buf
);

bool hostapd_get_mac_acl_info(
        const char *phy,
        const char *vif,
        struct schema_Wifi_VIF_State *vstate
);

bool hostapd_mac_acl_accept_add(const char *phy, const char *vif, const char *mac_list_buf);

bool hostapd_mac_acl_deny_add(const char *phy, const char *vif, const char *mac_list_buf);

int hostapd_mac_acl_clear(const char *phy, const char *vif);

bool hostapd_get_vif_status(const char *vif, const char *key, char *value);

int hostapd_chan_switch(
        const char *phy,
        const char *vif,
        int channel,
        char *center_freq1_str,
        char *sec_chan_offset_str,
        char *opt_chan_info
);

bool hostapd_sta_info(const char *vif, const char *mac, hostapd_sta_info_t *sta);

#endif /* HOSTAPD_UTIL_H_INCLUDED */
