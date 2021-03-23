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
 * Band Steering Abstraction Layer
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <assert.h>
#include <net/if.h>
#include <sys/types.h>
#define _LINUX_IF_H /* Avoid redefinition of stuff */
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/wireless.h>
#include <linux/rtnetlink.h>

#include <asm/byteorder.h>
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

#include "nl80211.h"
#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

#include "log.h"
#include "const.h"
#include "os_nif.h"
#include "evsched.h"
#include "ds_tree.h"

#include "target.h"
#include "bsal.h"
#include "hostapd_util.h"

#include <dirent.h>
#include <limits.h>
#include <linux/un.h>
#include <opensync-ctrl.h>
#include <opensync-wpas.h>
#include <opensync-hapd.h>
#include "wpa_ctrl.h"

/***************************************************************************************/

#define MODULE_ID           LOG_MODULE_ID_BSAL

/***************************************************************************************/

typedef __le16 le16;
typedef __le32 le32;

struct element {
    uint8_t id;
    uint8_t datalen;
    uint8_t data[];
};

struct ieee80211_hdr {
    le16 frame_control;
    le16 duration;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];
    le16 seq_ctrl;
};

struct ieee80211_mgmt {
    struct ieee80211_hdr hdr;
    union {
        struct {
            le16 capab_info;
            le16 listen_interval;
            uint8_t variable[];
        } assoc_req;
        struct {
            le16 capab_info;
            le16 listen_interval;
            uint8_t current_ap[6];
            uint8_t variable[];
        } reassoc_req;
    } u;
};

#define for_each_element(_elem, _data, _datalen)                        \
        for (_elem = (const struct element *) (_data);                  \
             (const uint8_t *) (_data) + (_datalen) - (const uint8_t *) _elem >=  \
                (int) sizeof(*_elem) &&                                 \
             (const uint8_t *) (_data) + (_datalen) - (const uint8_t *) _elem >=  \
                (int) sizeof(*_elem) + _elem->datalen;                  \
             _elem = (const struct element *) (_elem->data + _elem->datalen))

#define IEEE80211_HDRLEN (sizeof(struct ieee80211_hdr))
#define IEEE80211_FIXED_PARAM_LEN_ASSOC 4
#define IEEE80211_FIXED_PARAM_LEN_REASSOC 10
#define WLAN_EID_SUPP_RATES 1
#define WLAN_EID_RRM_ENABLED_CAPABILITIES 70
#define WLAN_EID_HT_CAP 45
#define WLAN_EID_EXT_SUPP_RATES 50
#define WLAN_EID_HT_OPERATION 61
#define WLAN_EID_EXT_CAPAB 127

#define BSAL_CLI_SNR_POLL_INTERVAL 5

#define BM_CLIENT_MAGIC_HWM 1

struct nl_global_info       bsal_nl_global;
static ev_async             bsal_nl_ev_async;
static ev_io                bsal_nl_ev_loop;
static ev_timer             bsal_cli_snr_poll;

static struct ev_loop       *_ev_loop           = NULL;
static bsal_event_cb_t      _bsal_event_cb      = NULL;

static ds_dlist_t bsal_cli_info_list = DS_DLIST_INIT(bsal_cli_info, node);

int bsal_nl_event_parse(struct nl_msg *msg, void *arg);

/***************************************************************************************/

static bsal_add_client(bsal_cli_info *client)
{
    ds_dlist_insert_tail(&bsal_cli_info_list, client);
    LOGI("%s: Added client " PRI(os_macaddr_t), __func__, FMT(os_macaddr_pt, &client->mac_addr));
}

static bsal_remove_client(bsal_cli_info *client)
{
    ds_dlist_remove(&bsal_cli_info_list, client);
    LOGI("%s: Removed client " PRI(os_macaddr_t), __func__, FMT(os_macaddr_pt, &client->mac_addr));
}

static bsal_cli_info* bsal_get_client(const char *ifname, const os_macaddr_t *mac_addr)
{
    bsal_cli_info *client;

    ds_dlist_foreach(&bsal_cli_info_list, client) {
        if (strncmp(client->ifname, ifname, IFNAMSIZ))
            continue;
        if (memcmp(&client->mac_addr, mac_addr, sizeof(client->mac_addr)))
            continue;

        return client;
    }

    return NULL;
}

/***************************************************************************************/

enum xing_level get_curr_snr_xing_status(int8_t snr, bsal_cli_info *client)
{
    if (snr < client->snr_lwm_xing) {
        return SNR_BELOW_LWM;
    } else if ((snr >= client->snr_lwm_xing) && (snr <= client->snr_hwm_xing)) {
        return SNR_BETWEEN_HWM_LWM;
    } else if (snr > client->snr_hwm_xing) {
        return SNR_ABOVE_HWM;
    }
}

bool check_snr_crossing_event(bsal_event_t *event,
                            enum xing_level old_xing,
                            enum xing_level new_xing)
{
    if (old_xing == SNR_ABOVE_HWM) {
        if (new_xing == SNR_BETWEEN_HWM_LWM) {
            event->data.rssi_change.high_xing = BSAL_RSSI_LOWER;
            event->data.rssi_change.low_xing = BSAL_RSSI_UNCHANGED;
        } else if (new_xing == SNR_BELOW_LWM) {
            event->data.rssi_change.high_xing = BSAL_RSSI_LOWER;
            event->data.rssi_change.low_xing = BSAL_RSSI_LOWER;
        }
    } else if (old_xing == SNR_BETWEEN_HWM_LWM) {
        if (new_xing == SNR_ABOVE_HWM) {
            event->data.rssi_change.high_xing = BSAL_RSSI_HIGHER;
            event->data.rssi_change.low_xing = BSAL_RSSI_UNCHANGED;
        } else if (new_xing == SNR_BELOW_LWM) {
            event->data.rssi_change.high_xing = BSAL_RSSI_UNCHANGED;
            event->data.rssi_change.low_xing = BSAL_RSSI_LOWER;
        }
    } else if (old_xing == SNR_BELOW_LWM) {
        if (new_xing == SNR_ABOVE_HWM) {
            event->data.rssi_change.high_xing = BSAL_RSSI_HIGHER;
            event->data.rssi_change.low_xing = BSAL_RSSI_HIGHER;
        } else if (new_xing == SNR_BETWEEN_HWM_LWM) {
            event->data.rssi_change.high_xing = BSAL_RSSI_UNCHANGED;
            event->data.rssi_change.low_xing = BSAL_RSSI_HIGHER;
        }
    } else if (old_xing == SNR_NONE) {
        if (new_xing == SNR_ABOVE_HWM) {
            event->data.rssi_change.high_xing = BSAL_RSSI_HIGHER;
            event->data.rssi_change.low_xing = BSAL_RSSI_UNCHANGED;
        } else if (new_xing == SNR_BELOW_LWM) {
            event->data.rssi_change.high_xing = BSAL_RSSI_UNCHANGED;
            event->data.rssi_change.low_xing = BSAL_RSSI_LOWER;
        } else if (new_xing == SNR_BETWEEN_HWM_LWM) {
            event->data.rssi_change.high_xing = BSAL_RSSI_UNCHANGED;
            event->data.rssi_change.low_xing = BSAL_RSSI_UNCHANGED;
            return false;
        }
    }
    return true;
}

void bsal_cli_rssi_xing(void)
{
    int8_t rssi = 0;
    bsal_cli_info *client;
    bsal_event_t event = { 0 };
    enum xing_level old_xing_level;

    ds_dlist_foreach(&bsal_cli_info_list, client) {
        if (!client->connected)
            continue;

        if (nl_req_get_sta_rssi(&bsal_nl_global, client->ifname, (uint8_t *) &client->mac_addr, &rssi) < 0) {
            LOGD("%s: Failed to get station information for "PRI(os_macaddr_t),
                 __func__, FMT(os_macaddr_t, client->mac_addr));
            continue;
        }

        if (rssi != 0) {
            event.data.rssi_change.rssi = rssi_to_snr(&bsal_nl_global, util_sys_ifname_to_idx(client->ifname), rssi);

            old_xing_level = client->xing_level;
            client->xing_level = get_curr_snr_xing_status(event.data.rssi_change.rssi, client);

            if (old_xing_level == client->xing_level)
                continue;

            event.type = BSAL_EVENT_RSSI_XING;
            STRSCPY(event.ifname, client->ifname);
            memcpy(&event.data.rssi_change.client_addr,
                   (uint8_t *) &client->mac_addr,
                   sizeof(event.data.rssi_change.client_addr));
            event.data.rssi_change.inact_xing = BSAL_RSSI_UNCHANGED;

            if (check_snr_crossing_event(&event, old_xing_level, client->xing_level)) {
                _bsal_event_cb(&event);
                LOGT("%s: bsal event.type:%d event.ifname:%s STA=" PRI(os_macaddr_t)
                     " snr=%d inact_xing=%d high_xing=%d low_xing=%d",
                     __func__, event.type, event.ifname,
                     FMT(os_macaddr_t, client->mac_addr),
                     event.data.rssi_change.rssi,
                     event.data.rssi_change.inact_xing,
                     event.data.rssi_change.high_xing,
                     event.data.rssi_change.low_xing);
            }
        }
    }
}

static void bsal_hapd_sta_connected(struct hapd *hapd, const char *mac, const char *keyid)
{
    bsal_event_t event = { 0 };
    os_macaddr_t bssid;
    bsal_cli_info *client;

    if (!os_nif_macaddr_from_str(&bssid, mac)) {
        LOGW("%s: failed to parse mac addr:%s", __func__, mac);
        return;
    }

    client = bsal_get_client(hapd->ctrl.bss, &bssid);
    if (!client) {
        client = calloc(1, sizeof(bsal_cli_info));
        STRSCPY(client->ifname, hapd->ctrl.bss);
        memcpy(&client->mac_addr, &bssid, sizeof(client->mac_addr));
        bsal_add_client(client);
    }
    client->connected = true;
    client->xing_level = SNR_NONE;

    event.type = BSAL_EVENT_CLIENT_CONNECT;

    STRSCPY(event.ifname, hapd->ctrl.bss);

    if (os_nif_macaddr_from_str(&bssid, mac))
        memcpy(&event.data.connect.client_addr, &bssid, sizeof(event.data.connect.client_addr));

    LOGI("%s: bsal event.type:%d event.ifname:%s station=" PRI(os_macaddr_t),
        __func__, event.type, event.ifname,
        FMT(os_macaddr_t, *(os_macaddr_t *) event.data.connect.client_addr));

    _bsal_event_cb(&event);
}

static void bsal_hapd_frame_disconnect(struct hapd *hapd, const char *in_buf)
{
    char         *kv;
    const char   *k;
    const char   *v;
    bsal_event_t event = { 0 };
    os_macaddr_t bssid;
    bsal_cli_info *client;

    event.type = BSAL_EVENT_CLIENT_DISCONNECT;

    STRSCPY(event.ifname, hapd->ctrl.bss);

    // NL80211-CMD-FRAME type=EVT_FRAME_DISCONNECT STA=40:b0:76:cf:b1:1a disconnect_type=deauth reason=1
    while ((kv = strsep(&in_buf, " "))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "STA")) {
                if (os_nif_macaddr_from_str(&bssid, v))
                    memcpy(&event.data.disconnect.client_addr, &bssid, sizeof(event.data.disconnect.client_addr));
            } else if (!strcmp(k, "disconnect_type")) {
                if (!strcmp(v, EVT_DISC_TYPE_DISASSOC))
                    event.data.disconnect.type = BSAL_DISC_TYPE_DISASSOC;
                else if (!strcmp(v, EVT_DISC_TYPE_DEAUTH))
                    event.data.disconnect.type = BSAL_DISC_TYPE_DEAUTH;
            } else if (!strcmp(k, "reason")) {
                event.data.disconnect.reason = atoi(v);
            }
        }
    }

    client = bsal_get_client(hapd->ctrl.bss, &bssid);
    if (client) {
        client->connected = false;
        client->xing_level = SNR_NONE;
    }

    LOGI("%s: bsal event.type:%d event.ifname:%s STA=" PRI(os_macaddr_t)
         " disconnect.type=%d disconnect.reason=%d",
         __func__, event.type, event.ifname,
         FMT(os_macaddr_t, *(os_macaddr_t *) event.data.disconnect.client_addr),
         event.data.disconnect.type, event.data.disconnect.reason);

    _bsal_event_cb(&event);

    return;
}

static void bsal_process_assoc_req_frame(const char *ifname, const char *frame, int reassoc)
{
    char                    *buf;
    const uint8_t           *ies;
    int                     buf_len = 0;
    int                     ies_len = 0;
    size_t                  alloc_buf_size = 0;
    bsal_cli_info           *client;
    struct ieee80211_mgmt   *mgmt;
    const struct element    *elem;
    const uint8_t           *ext_cap;
    const uint8_t           *rrm_cap;
    int                     fixed_param_len = 0;

    alloc_buf_size = strlen(frame) / 2;
    buf = calloc(alloc_buf_size, sizeof(uint8_t));
    if (!buf)
        return;

    hextobin(frame, strlen(frame), buf, &buf_len);

    mgmt = (struct ieee80211_mgmt *) buf;

    if (reassoc)
        fixed_param_len = IEEE80211_FIXED_PARAM_LEN_REASSOC;
    else
        fixed_param_len = IEEE80211_FIXED_PARAM_LEN_ASSOC;

    // TODO: use u.(re)assoc_req.variable instead of calulating ies position
    ies = ((const uint8_t *) buf) + IEEE80211_HDRLEN + fixed_param_len;
    ies_len = buf_len - IEEE80211_HDRLEN - fixed_param_len;
    if (ies_len <= 0)
        goto error;

    client = bsal_get_client(ifname, mgmt->hdr.sa);
    if (!client) {
        client = calloc(1, sizeof(bsal_cli_info));
        STRSCPY(client->ifname, ifname);
        memcpy(&client->mac_addr, mgmt->hdr.sa, sizeof(client->mac_addr));
        client->connected = false; // Mark as connected on AP-STA-CONNECTED event from hostapd
        bsal_add_client(client);
    }

    if (ies_len < sizeof(client->assoc_ies)) {
        memcpy(client->assoc_ies, ies, ies_len);
        client->assoc_ies_len = ies_len;
    } else {
        LOGI("%s: received assoc ies length[%d] exceeds buffer len[%d]",
             __func__, ies_len, sizeof(client->assoc_ies));
    }

    for_each_element(elem, ies, ies_len) {
        switch (elem->id) {
            case WLAN_EID_EXT_CAPAB:
                ext_cap = elem->data;
                if (ext_cap && elem->datalen > 2)
                    client->is_BTM_supported = !!(ext_cap[2] & 0x08);
                break;
            case WLAN_EID_RRM_ENABLED_CAPABILITIES:
                rrm_cap = elem->data;
                if (rrm_cap && elem->datalen > 0) {
                    client->is_RRM_supported = !!(rrm_cap[0] & 0x01);
                    client->rrm_caps.neigh_rpt = !!(rrm_cap[0] & 0x02);
                    client->rrm_caps.bcn_rpt_passive = !!(rrm_cap[0] & 0x16);
                    client->rrm_caps.bcn_rpt_active = !!(rrm_cap[0] & 0x32);
                    client->rrm_caps.bcn_rpt_table = !!(rrm_cap[0] & 0x64);
                }
                break;
            default:
                break;
        }
    }

    LOGI("%s: station=" PRI(os_macaddr_t)
         " is_BTM_supported[%d] is_RRM_supported[%d]"
         "rrm_caps.neigh_rpt[%d] rrm_caps.bcn_rpt_passive[%d]"
         "rrm_caps.bcn_rpt_active[%d] rrm_caps.bcn_rpt_table[%d]"
         "assoc_ies_len[%d]",
         __func__,
         FMT(os_macaddr_t, client->mac_addr),
         client->is_BTM_supported,
         client->is_RRM_supported,
         client->rrm_caps.neigh_rpt,
         client->rrm_caps.bcn_rpt_passive,
         client->rrm_caps.bcn_rpt_active,
         client->rrm_caps.bcn_rpt_table,
         client->assoc_ies_len);

    free(buf);

    return 0;

error:
    free(buf);
    return -1;
}

static void nl80211_cmd_frame_event(struct hapd *hapd, const char *in_buf)
{
    char        *kv;
    const char  *k;
    const char  *v;
    char        *parse_buf = strdupa(in_buf);
    char        assoc_frame[BFR_SIZE_1K] = { 0 };
    int         reassoc = 0;

    if (strstr(parse_buf, EVT_FRAME_REASSOC_REQ))
        reassoc = 1;

    // NL80211-CMD-FRAME type=EVT-FRAME-ASSOC-REQ buf=<frame hex dump>
    if (strstr(parse_buf, EVT_FRAME_ASSOC_REQ) || strstr(parse_buf, EVT_FRAME_REASSOC_REQ))
        while ((kv = strsep(&parse_buf, " ")))
            if ((k = strsep(&kv, "=")) && (v = strsep(&kv, "")))
                if (!strcmp(k, "buf")) {
                    STRSCPY(assoc_frame, v);
                    bsal_process_assoc_req_frame(hapd->ctrl.bss, assoc_frame, reassoc);
                }
}

static void bsal_hapd_frame_action(struct hapd *hapd, const char *in_buf)
{
    char            *kv;
    const char      *k;
    const char      *v;
    char            *buf;
    char            *hex_buf = NULL;
    int             buf_len = 0;
    size_t          alloc_buf_size = 0;
    bsal_event_t    event;

    memset(&event, 0, sizeof(event));

    while ((kv = strsep(&in_buf, " "))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "buf")) {
                hex_buf = v;
                break;
            }
        }
    }

    if (!hex_buf)
        return;

    alloc_buf_size = strlen(hex_buf) / 2;
    buf = calloc(alloc_buf_size, sizeof(uint8_t));
    if (!buf)
        return;

    hextobin(hex_buf, strlen(hex_buf), buf, &buf_len);

    event.type = BSAL_EVENT_ACTION_FRAME;
    STRSCPY(event.ifname, hapd->ctrl.bss);
    memcpy(event.data.action_frame.data, buf, buf_len);
    event.data.action_frame.data_len = buf_len;

    LOGI("%s: bsal event.type:%d event.ifname:%s action_frame.data_len:%d",
         __func__, event.type, event.ifname, event.data.action_frame.data_len);

    _bsal_event_cb(&event);

    free(buf);

    return;
}

static void bsal_hapd_frame_probe_req(struct hapd *hapd, const char *buf)
{
    char            *kv;
    const char      *k;
    const char      *v;
    bsal_event_t    event;
    os_macaddr_t    bssid;

    memset(&event, 0, sizeof(event));

    event.type = BSAL_EVENT_PROBE_REQ;

    STRSCPY(event.ifname, hapd->ctrl.bss);

    // NL80211-CMD-FRAME type=EVT-FRAME-PROBE-REQ sa=9a:00:80:9d:d4:66 ssi_signal=-79 ssid_null=1
    while ((kv = strsep(&buf, " "))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "ssi_signal")) {
                event.data.probe_req.rssi = rssi_to_snr(&bsal_nl_global,
                                                        util_sys_ifname_to_idx(hapd->ctrl.bss),
                                                        atoi(v));
            }
            if (!strcmp(k, "ssid_null"))
                event.data.probe_req.ssid_null = atoi(v);
            if (!strcmp(k, "sa"))
                if (os_nif_macaddr_from_str(&bssid, v))
                    memcpy(&event.data.probe_req.client_addr, &bssid, sizeof(event.data.probe_req.client_addr));
        }
    }
    event.data.probe_req.blocked = false;

    LOGI("%s: bsal event.type:%d probe_req.rssi:%d probe_req.ssid_null:%d " PRI(os_macaddr_t),
         __func__, event.type, event.data.probe_req.rssi, event.data.probe_req.ssid_null,
         FMT(os_macaddr_t, *(os_macaddr_t *)event.data.probe_req.client_addr));

    _bsal_event_cb(&event);

    return;
}

int hostap_init_bss(const char *bss)
{
    const char *phy;
    char p_buf[BFR_SIZE_32] = {0};
    struct hapd *hapd = hapd_lookup(bss);

    if (util_get_vif_radio(bss, p_buf, sizeof(p_buf))) {
        LOGW("%s: failed to get bss radio", bss);
        return -1;
    }
    phy = strdupa(p_buf);

    if (!hapd)
        hapd = hapd_new(phy, bss);

    if (WARN_ON(!hapd))
        return -1;

    hapd->sta_connected = bsal_hapd_sta_connected;
    hapd->cmd_frame = nl80211_cmd_frame_event;
    hapd->cmd_frame_probe_req = bsal_hapd_frame_probe_req;
    hapd->cmd_frame_action = bsal_hapd_frame_action;
    hapd->cmd_frame_disconnect = bsal_hapd_frame_disconnect;

    if (!ctrl_enable(&hapd->ctrl))
        LOGI("%s: bsal hapd initialized for %s", __func__, bss);

    hapd = NULL;

    return 0;
}

static int bsal_bs_config(
        const bsal_ifconfig_t *ifcfg,
        bool enable)
{
    if (enable) {
        if (hostap_init_bss(ifcfg->ifname) < 0) {
            LOGW("%s: failed to initialize hapd for bss", ifcfg->ifname);
            return -1;
        }
    }

    return 0;
}

int nl_bsal_iface_add(const bsal_ifconfig_t *ifcfg)
{
    if (bsal_bs_config(ifcfg, true) < 0)
        return -1;

    return 0;
}

int nl_bsal_iface_update(const bsal_ifconfig_t *ifcfg)
{
    if (bsal_bs_config(ifcfg, true) < 0)
        return -1;

    return 0;
}

int nl_bsal_iface_remove(const bsal_ifconfig_t *ifcfg)
{
    bsal_bs_config(ifcfg, false);

    return 0;
}

static int hapd_cli_bsal_acl_mac(
        const char *ifname,
        const uint8_t *mac_addr,
        bool add)
{
    if (!hostapd_deny_acl_update(ifname, mac_addr, add)) {
        LOGN("Failed to update MAC ACL list");
        return -1;
    }

    LOGI("%s: %s MAC DENY_ACL list updated - %s mac=" PRI(os_macaddr_t),
         __func__, ifname, add ? "blocked" : "unblocked", FMT(os_macaddr_t, *(os_macaddr_t *) mac_addr));

    return 0;
}

static int bsal_bs_client_config(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_client_config_t *conf)
{
    bsal_cli_info *client;

    client = bsal_get_client(ifname, mac_addr);
    if (client) {
        client->snr_lwm_xing = conf->rssi_low_xing;
        client->snr_hwm_xing = conf->rssi_high_xing;
        LOGT("%s: station "PRI(os_macaddr_t)" - xing low=%d high=%d updated",
             __func__, FMT(os_macaddr_t, client->mac_addr),
             client->snr_lwm_xing, client->snr_hwm_xing);
    }

    // Blacklist station if not connected and HWM == 1
    if (conf->rssi_probe_hwm == BM_CLIENT_MAGIC_HWM) {
        if (!client->connected)
            hapd_cli_bsal_acl_mac(ifname, mac_addr, true);
    } else if (!conf->rssi_probe_hwm) {
        hapd_cli_bsal_acl_mac(ifname, mac_addr, false);
    }

    return 0;
}

int nl_bsal_client_add(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_client_config_t *conf)
{
    int ret;
    bsal_cli_info *client;

    client = bsal_get_client(ifname, mac_addr);
    if (!client) {
        client = calloc(1, sizeof(bsal_cli_info));
        STRSCPY(client->ifname, ifname);
        memcpy(&client->mac_addr, mac_addr, sizeof(client->mac_addr));
        bsal_add_client(client);
    }

    return bsal_bs_client_config(ifname, mac_addr, conf);
}

int nl_bsal_client_update(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_client_config_t *conf)
{
    return bsal_bs_client_config(ifname, mac_addr, conf);
}

int nl_bsal_client_remove(
        const char *ifname,
        const uint8_t *mac_addr)
{
    bsal_cli_info *client;

    if (client = bsal_get_client(ifname, mac_addr))
        bsal_remove_client(client);

    return hapd_cli_bsal_acl_mac(ifname, mac_addr, false);
}

int nl_bsal_client_measure(
        const char *ifname,
        const uint8_t *mac_addr,
        int num_samples)
{
    int8_t rssi = 0;
    bsal_event_t event;

    if (nl_req_get_sta_rssi(&bsal_nl_global, ifname, mac_addr, &rssi) < 0) {
        LOGW("Failed to get station information");
        return -EINVAL;
    }

    event.type = BSAL_EVENT_RSSI;
    STRSCPY(event.ifname, ifname);
    memcpy(&event.data.rssi.client_addr, mac_addr, sizeof(event.data.rssi.client_addr));
    event.data.rssi.rssi = rssi_to_snr(&bsal_nl_global, util_sys_ifname_to_idx(ifname), rssi);

    LOGI("%s: bsal event.type:%d event.ifname:%s rssi:%d" PRI(os_macaddr_t),
         __func__, event.type, event.ifname, event.data.rssi.rssi,
         FMT(os_macaddr_t, *(os_macaddr_t *) event.data.rssi.client_addr));

    _bsal_event_cb(&event);

    return 0;
}

int nl_bsal_client_info(
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_client_info_t *info)
{
    bsal_cli_info *client = bsal_get_client(ifname, mac_addr);

    if (!client) {
        info->connected = false;
        return -1;
    }

    memset(info, 0, sizeof(info));

    info->is_BTM_supported = client->is_BTM_supported;
    info->is_RRM_supported = client->is_RRM_supported;
    //info->datarate_info.max_chwidth = client->datarate_info.max_chwidth;
    //info->datarate_info.max_streams = client->datarate_info.max_streams;
    //info->datarate_info.max_MCS = client->datarate_info.max_MCS;
    info->rrm_caps.link_meas = client->rrm_caps.link_meas;
    info->rrm_caps.neigh_rpt = client->rrm_caps.neigh_rpt;
    info->rrm_caps.bcn_rpt_passive = client->rrm_caps.bcn_rpt_passive;
    info->rrm_caps.bcn_rpt_active = client->rrm_caps.bcn_rpt_active;
    info->rrm_caps.bcn_rpt_table = client->rrm_caps.bcn_rpt_table;

    memcpy(info->assoc_ies, client->assoc_ies, sizeof(info->assoc_ies));
    info->assoc_ies_len = client->assoc_ies_len;

    nl_req_get_sta_info(&bsal_nl_global, ifname, mac_addr, client);

    info->snr = client->snr;
    info->connected = client->connected;
    info->rx_bytes = client->rx_bytes;
    info->tx_bytes = client->tx_bytes;

    return 0;
}

static bool hapd_cli_bss_tm_request(
        const char *client_mac,
        const char *interface,
        const bsal_btm_params_t *btm_params)
{
    int             i;
    char            btm_req_cmd[BFR_SIZE_1K]   = { 0 };
    char            neigh_list[BFR_SIZE_512]   = { 0 };
    char            cmd[BFR_SIZE_128]          = { 0 };
    char            mac_str[MAC_ADDR_STR_SIZE] = { 0 };
    os_macaddr_t    temp;
    const bsal_neigh_info_t *neigh = NULL;

    for (i = 0; i < btm_params->num_neigh; i++) {
        neigh = &btm_params->neigh[i];

        memset(&mac_str, 0, sizeof(mac_str));
        memset(&cmd, 0, sizeof(cmd));
        memset(&temp,0, sizeof(temp));

        memcpy(&temp, neigh->bssid, sizeof(temp));
        sprintf(mac_str, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

        snprintf(cmd, sizeof(cmd),
                 "neighbor=%s,%u,%hhu,%hhu,%hhu ",
                 mac_str, neigh->bssid_info, neigh->op_class,
                 neigh->channel, neigh->phy_type);

        strcat(neigh_list, cmd);
    }

    snprintf(btm_req_cmd, sizeof(btm_req_cmd),
             "%s %s valid_int=%hhu pref=%hhu abridged=%hhu disassoc_imminent=%hhu",
             client_mac, (strlen(neigh_list) ? neigh_list : ""),
             btm_params->valid_int, btm_params->pref, btm_params->abridged,
             btm_params->disassoc_imminent);

    LOGI("%s: ifname=%s bss_tm_req %s", __func__, interface, btm_req_cmd);

    return hostapd_btm_request(interface, btm_req_cmd);
}

static bool hapd_cli_rrm_bcn_rpt_request(
        const char *client_mac,
        const char *interface,
        const bsal_rrm_params_t *rrm_params)
{
    char        rrm_bcn_rpt_cmd[BFR_SIZE_1K]   = { 0 };
    bool        ret                     = false;
    char        cur_ssid[BFR_SIZE_128]           = { 0 };
    char        hex_ssid[BFR_SIZE_128]           = { 0 };

    if (rrm_params->req_ssid == 1) {
        nl_req_get_ssid(&bsal_nl_global, interface, cur_ssid);
        if (bintohex((const uint8_t *) cur_ssid, strlen(cur_ssid), hex_ssid, sizeof(hex_ssid)) < 0)
            LOGW("Failed to fetch ssid");
    }

    snprintf(rrm_bcn_rpt_cmd, sizeof(rrm_bcn_rpt_cmd),
             "%02x"         // Operating Class
             "%02x"         // Channel Number
             "%02x00"       // Randomization Interval
             "%02x00"       // Measurement Duration
             "%02x"         // Measurement Mode
             "ffffffffffff" // BSSID
             "00%02x"       // Optional Subelements: SSID len
             "%s"           // Optional Subelements: SSID
             "0102"         // Optional Subelements: Reporting Condition len
             "%02x00"       // Optional Subelements: Reporting Condition
             "0201"         // Optional Subelements: Reporting Detail len
             "%02x",        // Optional Subelements: Reporting Detail
             rrm_params->op_class,
             rrm_params->channel,
             rrm_params->rand_ivl,
             rrm_params->meas_dur,
             rrm_params->meas_mode,
             (strlen(hex_ssid)/2),
             hex_ssid,
             rrm_params->rep_cond,
             rrm_params->rpt_detail);

    LOGI("%s: ifname=%s req_beacon %s measurement_request_hexdump=%s",
         __func__, interface, client_mac, rrm_bcn_rpt_cmd);

    return hostapd_rrm_beacon_report_request(interface, client_mac, rrm_bcn_rpt_cmd);
}

int nl_bsal_client_disconnect(
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_disc_type_t type,
        uint8_t reason)
{
    bool            ret         = false;
    char            *disc_type  = NULL;
    char            mac_str[MAC_ADDR_STR_SIZE];
    os_macaddr_t    temp;

    switch (type)
    {
        case BSAL_DISC_TYPE_DISASSOC:
            disc_type = "disassociate";
            break;

        case BSAL_DISC_TYPE_DEAUTH:
            disc_type = "deauth";
            break;

        default:
            return -1;
    }

    memcpy(&temp, mac_addr, sizeof(temp));
    sprintf(mac_str, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

    ret = hostapd_client_disconnect(ifname, disc_type, mac_str, reason);
    if (!ret) {
        LOGW("%s: failed to disassociate/deauth station", __func__);
        return -1;
    }

    return 0;
}

int nl_bsal_bss_tm_request(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_btm_params_t *btm_params)
{
    os_macaddr_t    temp;
    char            client_mac[MAC_ADDR_STR_SIZE] = { 0 };
    bool            ret = false;

    memcpy(&temp, mac_addr, sizeof(temp));
    sprintf(client_mac, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

    ret = hapd_cli_bss_tm_request(client_mac, ifname, btm_params);
    if (!ret) {
        LOGW("%s: failed to send BSS Transition Management Request", __func__);
        return -1;
    }

    return 0;
}

int nl_bsal_rrm_beacon_report_request(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_rrm_params_t *rrm_params)
{
    os_macaddr_t    temp;
    char            client_mac[MAC_ADDR_STR_SIZE] = { 0 };
    bool            ret = false;

    memcpy(&temp, mac_addr, sizeof(temp));
    sprintf(client_mac, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

    ret = hapd_cli_rrm_bcn_rpt_request(client_mac, ifname, rrm_params);
    if (!ret) {
        LOGW("%s: failed to send Beacon report request", __func__);
        return -1;
    }

    return 0;
}

int nl_bsal_rrm_set_neighbor(
        const char *ifname,
        const bsal_neigh_info_t *neigh)
{
    os_macaddr_t    temp;
    char            bssid[MAC_ADDR_STR_SIZE] = { 0 };
    char            nr[BFR_SIZE_256]         = { 0 };
    char            cur_ssid[BFR_SIZE_128]   = { 0 };
    char            hex_ssid[BFR_SIZE_128]   = { 0 };

    nl_req_get_ssid(&bsal_nl_global, ifname, cur_ssid);
    if (bintohex((const uint8_t *) cur_ssid, strlen(cur_ssid), hex_ssid, sizeof(hex_ssid)) < 0)
        LOGW("Failed to fetch ssid");

    memcpy(&temp, neigh->bssid, sizeof(temp));
    sprintf(bssid, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

    snprintf(nr, sizeof(nr),
             "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"  // bssid
             "%02hhx%02hhx%02hhx%02hhx"              // bssid_info
             "%02hhx"                                // operclass
             "%02hhx"                                // channel
             "%02hhx",                               // phy_mode
             neigh->bssid[0], neigh->bssid[1], neigh->bssid[2], neigh->bssid[3], neigh->bssid[4], neigh->bssid[5],
             neigh->bssid_info & 0xff, (neigh->bssid_info >> 8) & 0xff,
             (neigh->bssid_info >> 16) & 0xff, (neigh->bssid_info >> 24) & 0xff,
             neigh->op_class,
             neigh->channel,
             neigh->phy_type);

    if (!hostapd_rrm_set_neighbor(ifname, bssid, hex_ssid, nr))
        return -1;

    LOGI("%s: ifname=%s set_neighbor bssid=%s ssid=%s nr=%s",
         __func__, ifname, bssid, hex_ssid, nr);

    return 0;
}

int nl_bsal_rrm_remove_neighbor(
        const char *ifname,
        const bsal_neigh_info_t *neigh)
{
    os_macaddr_t temp;
    char bssid[MAC_ADDR_STR_SIZE] = { 0 };

    memcpy(&temp, neigh->bssid, sizeof(temp));
    sprintf(bssid, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

    if (!hostapd_rrm_remove_neighbor(ifname, bssid))
        return -1;

    LOGI("%s: ifname=%s remove_neighbor bssid=%s", __func__, ifname, bssid);

    return 0;
}

int nl_bsal_send_action(
        const char *ifname,
        const uint8_t *mac_addr,
        const uint8_t *data,
        unsigned int data_len)
{
    return 0;
}

void bsal_nl_evt_parse_conn_failed(struct nlattr **tb)
{
    int reason;
    bsal_event_t event = { 0 };

    if (!tb[NL80211_ATTR_MAC] || !tb[NL80211_ATTR_CONN_FAILED_REASON])
        return;

    event.type = BSAL_EVENT_AUTH_FAIL;
    memcpy(&event.data.auth_fail.client_addr, nla_data(tb[NL80211_ATTR_MAC]), BSAL_MAC_ADDR_LEN);
    event.data.auth_fail.rssi   = 0; /* TODO: Currently unavailable */
    event.data.auth_fail.reason = 1; /* Unspecified */

    if (tb[NL80211_ATTR_IFNAME])
        strscpy(event.ifname, nla_get_string(tb[NL80211_ATTR_IFNAME]), IFNAMSIZ);

    reason = nla_get_u32(tb[NL80211_ATTR_CONN_FAILED_REASON]);
    switch (reason) {
    case NL80211_CONN_FAIL_MAX_CLIENTS:
        /* Maximum number of clients that can be handled by the AP is reached */
        event.data.auth_fail.bs_rejected = 1;
        LOGI("%s: Max client reached", __func__);
        break;
    case NL80211_CONN_FAIL_BLOCKED_CLIENT:
        /* Connection request is rejected due to ACL */
        event.data.auth_fail.bs_blocked = 1;
        event.data.auth_fail.bs_rejected = 1;
        LOGI("%s: Blocked client " PRI(os_macaddr_t), __func__,
             FMT(os_macaddr_t, *(os_macaddr_t *)event.data.auth_fail.client_addr));
        break;
    default:
        LOGI("%s: Unknown connect failed reason %u", __func__, reason);
        break;
    }

    LOGI("%s: Sending BSAL_EVENT_AUTH_FAIL for mac=" PRI(os_macaddr_t)
         " with reason=%d bs_rejected=%d bs_blocked=%d rssi=%d",
         __func__,
        FMT(os_macaddr_t, *(os_macaddr_t *)event.data.auth_fail.client_addr),
        event.data.auth_fail.reason,
        event.data.auth_fail.bs_rejected,
        event.data.auth_fail.bs_blocked,
        event.data.auth_fail.rssi);

    _bsal_event_cb(&event);

    return;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}

static int err_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    return NL_SKIP;
}

static int no_seq_check(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

void bsal_nl_ev_handler(struct ev_loop *ev, struct ev_io *io, int event)
{
    int res = -EINVAL;

    nl_cb_err(bsal_nl_global.nl_cb, NL_CB_CUSTOM, err_handler, NULL);
    nl_cb_set(bsal_nl_global.nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);
    nl_cb_set(bsal_nl_global.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(bsal_nl_global.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, bsal_nl_event_parse, NULL);

    res = nl_recvmsgs(bsal_nl_global.nl_evt_handle, bsal_nl_global.nl_cb);
    if (res < 0)
        LOGT("Failed to receive event message");
}

void bsal_nl_global_init()
{
    add_mcast_subscription(&bsal_nl_global, "mlme");

    ev_io_init(&bsal_nl_ev_loop, bsal_nl_ev_handler, nl_socket_get_fd(bsal_nl_global.nl_evt_handle), EV_READ);
    ev_io_start(_ev_loop, &bsal_nl_ev_loop);

    return;
}

void bsal_nl_global_async_init()
{
    ev_async_init(&bsal_nl_ev_async, bsal_nl_global_init);
    ev_async_start(_ev_loop, &bsal_nl_ev_async);
    ev_async_send(_ev_loop, &bsal_nl_ev_async);
}

int nl_bsal_init(
        bsal_event_cb_t event_cb,
        struct ev_loop *loop)
{
    if (_ev_loop) {
        LOGE("%s: bsal event loop already initialized", __func__);
        return 0;
    }

    _ev_loop = loop;
    _bsal_event_cb = event_cb;

    if (WARN_ON(netlink_init(&bsal_nl_global) < 0))
        return -1;

    bsal_nl_global_async_init();

    ev_timer_init(&bsal_cli_snr_poll, bsal_cli_rssi_xing,
                  BSAL_CLI_SNR_POLL_INTERVAL,
                  BSAL_CLI_SNR_POLL_INTERVAL);
    ev_timer_start(_ev_loop, &bsal_cli_snr_poll);

    LOGI("%s: bsal event loop initialized", __func__);

    return 0;
}

int nl_bsal_cleanup(void)
{
    LOGI("%s: cleaning up", __func__);

    ev_timer_stop(_ev_loop, &bsal_cli_snr_poll);

    nl_socket_free(bsal_nl_global.nl_msg_handle);
    nl_socket_free(bsal_nl_global.nl_evt_handle);
    nl_cb_put(bsal_nl_global.nl_cb);
    bsal_nl_global.nl_cb = NULL;
    ev_io_stop(_ev_loop, &bsal_nl_ev_loop);
    ev_async_stop(_ev_loop, &bsal_nl_ev_async);

    _ev_loop = NULL;
    _bsal_event_cb = NULL;

    return 0;
}
