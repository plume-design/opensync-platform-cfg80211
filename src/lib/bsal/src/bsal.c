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
#include "ds_tree.h"

#include "target.h"
#include "bsal.h"
#include "hostapd_util.h"
#include "target_util.h"

#include <dirent.h>
#include <limits.h>
#include <linux/un.h>
#include <opensync-ctrl.h>
#include <opensync-wpas.h>
#include <opensync-hapd.h>
#include "wpa_ctrl.h"
#include "kconfig.h"
#include "ovsdb_sync.h"
#include "util.h"

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

#define BSAL_HOSTAP_CTRL_MAX_RETRY 60

struct bsal_hostap_ctrl_try {
    struct ctrl *ctrl;
    ev_timer timer;
    int retry_cnt;
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

#define IEEE80211_HT_RATE_SIZE (16 * 8)
#define MAX_VHT_STREAMS (8)

#define BSAL_CLI_SNR_POLL_INTERVAL 5

#define BM_CLIENT_MAGIC_HWM 1

/* HT capability flags */
#define IEEE80211_HTCAP_C_CHWIDTH40             0x0002
#define IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC    0x0000  /* Capable of SM Power Save (Static) */
#define IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC   0x0004  /* Capable of SM Power Save (Dynamic) */
#define IEEE80211_HTCAP_C_SM_RESERVED           0x0008  /* Reserved */
#define IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED  0x000C  /* SM enabled, no SM Power Save */
#define IEEE80211_HTCAP_C_SMPOWERSAVE_MASK      0X000C
#define IEEE80211_HTCAP_C_SMPOWERSAVE_S         2
#define IEEE80211_HTCAP_C_GREENFIELD            0x0010
#define IEEE80211_HTCAP_C_SHORTGI20             0x0020
#define IEEE80211_HTCAP_C_SHORTGI40             0x0040

#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80      0x00000000  /* Does not support 160 or 80+80 */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160     0x00000004  /* Supports 160 */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160  0x00000008  /* Support both 160 or 80+80 */

#define HE_NSS_MAX_STREAMS                      8

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

#define HE_PHYCAP_CHANNEL_WIDTH_SET_IDX                 0
#define HE_PHYCAP_CHANNEL_WIDTH_MASK                    ((uint8_t) (BIT(1) | BIT(2) | BIT(3) | BIT(4)))
#define HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_IN_2G         ((uint8_t) BIT(1))
#define HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G   ((uint8_t) BIT(2))
#define HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G        ((uint8_t) BIT(3))
#define HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G   ((uint8_t) BIT(4))

#define EV(x) strchomp(strdupa(x), " ")

static inline uint16_t bsal_get_le16(const uint8_t *a)
{
    return (a[1] << 8) | a[0];
}

struct nl_global_info       bsal_nl_global;
static ev_async             bsal_nl_ev_async;
static ev_io                bsal_nl_ev_loop;
static ev_timer             bsal_cli_snr_poll;

static struct ev_loop       *_ev_loop           = NULL;
static bsal_event_cb_t      _bsal_event_cb      = NULL;

static ds_dlist_t bsal_cli_info_list = DS_DLIST_INIT(bsal_cli_info, node);

int bsal_nl_event_parse(struct nl_msg *msg, void *arg);

/* get num of spatial streams from mcs rate */
static int ht_mcs_to_numstreams(int mcs)
{
    int numstreams = 0;

    /* single stream mcs rates */
    if ((mcs <= 7) || (mcs == 32))
        numstreams = 1;
    /* two streams mcs rates */
    if (((mcs >= 8) && (mcs <= 15)) || ((mcs >= 33) && (mcs <= 38)))
        numstreams = 2;
    /* three streams mcs rates */
    if (((mcs >= 16) && (mcs <= 23)) || ((mcs >= 39) && (mcs <= 52)))
        numstreams = 3;
    /* four streams mcs rates */
    if (((mcs >= 24) && (mcs <= 31)) || ((mcs >= 53) && (mcs <= 76)))
        numstreams = 4;

    return numstreams;
}

static int get_ht_nss_max(const uint8_t *mcsset)
{
    int i;
    int numstreams = 0, max_numstreams = 0;
    for (i=0; i < IEEE80211_HT_RATE_SIZE; i++) {
        if (mcsset[i/8] & (1<<(i%8))) {
            /* update the num of streams supported */
            numstreams = ht_mcs_to_numstreams(i);
            if (max_numstreams < numstreams)
                max_numstreams = numstreams;
        }
    }
    return max_numstreams;
}

static int get_ht_mcs_max(const uint8_t *mcsset)
{
    int i;

    if (!mcsset)
        return 0;

    for (i = (IEEE80211_HT_RATE_SIZE - 1); i >= 0; i--)
    {
        if (i < 32 && (mcsset[i/8] & (1<<(i%8))))
            return i;
    }
    return 0;
}

static int get_vht_numstreams(uint16_t map)
{
    int i = 0;
    u_int8_t n;
    int numstreams = 0;

    for (i = 0; i < MAX_VHT_STREAMS; i++) {
        n  = map & 0x03;
        if (n < 3) {
            /*
              This is to get nss based on vht_map,
              for some config e.g. 11,11,01,11, original code will get only nss = 1,
              which's wrong, nss should be 2 in this case.
            */
            numstreams = i + 1;
        }
        map = map >> 2;
    }
    return numstreams;
}

static int get_vht_mcs_max(uint16_t map)
{
    int i;
    int max = 0;

    for (i = 0; i < MAX_VHT_STREAMS; i++) {
        int a = map & 0x03;
        switch (a)
        {
            case 0: if (max < 7) max = 7; break;
            case 1: if (max < 8) max = 8; break;
            case 2: if (max < 9) max = 9; break;
            default: break;
        }
        map >>= 2;
    }
    return max;
}

static int get_he_nss_max(const uint16_t *mcsset, uint8_t mcs_count)
{
    uint16_t rxmcs;
    int max = 0;
    int i;
    int j;

    if (!mcsset)
        return 0;

    /* 80, 160, 80+80, interleaved tx/rx */
    for (i = 0; i < mcs_count; i++)
    {
        rxmcs = bsal_get_le16((const uint8_t *) &mcsset[(i*2)]);
        for (j = 0; j < HE_NSS_MAX_STREAMS; j++, rxmcs >>= 2)
            if ((rxmcs & 0x03) != 3)
                if (j > max)
                    max = j;
    }

    return max + 1;
}

static int get_he_mcs_max(const uint16_t *mcsset, uint8_t mcs_count)
{
    uint16_t rxmcs;
    int max = 0;
    int i;
    int j;

    if (!mcsset)
        return 0;

    /* 80, 160, 80+80, interleaved tx/rx */
    for (i = 0; i < mcs_count; i++)
    {
        rxmcs = bsal_get_le16((const uint8_t *) &mcsset[(i*2)]);
        for (j = 0; j < HE_NSS_MAX_STREAMS; j++, rxmcs >>= 2)
        {
            switch (rxmcs & 0x03)
            {
                case 0: if (max < 7) max = 7; break;
                case 1: if (max < 9) max = 9; break;
                case 2: if (max < 11) max = 11; break;
                case 3: break;
            }
        }
    }

    return max;
}

static uint8_t ieee80211_he_mcs_count(const uint8_t *phy_cap_info)
{
    uint8_t sz = 1;
    if (phy_cap_info[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
        HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G) {
        sz += 1;
    }
    if (phy_cap_info[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
        HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G) {
        sz += 1;
    }
    return sz;
}

static bsal_max_chwidth_t get_max_chwidth(hostapd_sta_info_t *sta)
{
    bsal_max_chwidth_t max_chwidth = BSAL_MAX_CHWIDTH_20MHZ;
    if (sta->ht_caps_info & IEEE80211_HTCAP_C_CHWIDTH40) {
        max_chwidth = BSAL_MAX_CHWIDTH_40MHZ;
    }
    if (sta->vht_caps_info > 0) {
        max_chwidth = BSAL_MAX_CHWIDTH_80MHZ;
        if (sta->vht_caps_info & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160) {
            max_chwidth = BSAL_MAX_CHWIDTH_160MHZ;
        }
    }

    if (sta->he_phy_capab_info[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
        HE_PHYCAP_CHANNEL_WIDTH_MASK) {

        if ((sta->he_phy_capab_info[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
            HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G) ||
            (sta->he_phy_capab_info[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
            HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G)) {

            max_chwidth = BSAL_MAX_CHWIDTH_160MHZ;
        }
        else if (sta->he_phy_capab_info[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
            HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G) {

            max_chwidth = BSAL_MAX_CHWIDTH_80MHZ;
        }
        else if (sta->he_phy_capab_info[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
            HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_IN_2G) {

            max_chwidth = BSAL_MAX_CHWIDTH_40MHZ;
        }
    }
    return max_chwidth;
}

static bsal_phy_mode_t sta_get_phy_mode(bsal_cli_info *data, hostapd_sta_info_t *sta)
{
    bsal_phy_mode_t phy_mode = BSAL_PHY_MODE_AUTO;
    if (sta->vht_caps_info > 0) {
        switch (data->datarate_info.max_chwidth) {
            case BSAL_MAX_CHWIDTH_160MHZ:
                phy_mode = BSAL_PHY_MODE_11AC_VHT160;
                break;
            case BSAL_MAX_CHWIDTH_80MHZ:
                phy_mode = BSAL_PHY_MODE_11AC_VHT80;
                break;
            case BSAL_MAX_CHWIDTH_40MHZ:
                phy_mode = BSAL_PHY_MODE_11AC_VHT40;
                break;
            case BSAL_MAX_CHWIDTH_20MHZ:
                phy_mode = BSAL_PHY_MODE_11AC_VHT20;
            default:
                break;
        }
    } else if (sta->ht_caps_info > 0) {
        switch (data->datarate_info.max_chwidth) {
            case BSAL_MAX_CHWIDTH_40MHZ:
                phy_mode = BSAL_PHY_MODE_11NG_HT40;
                break;
            case BSAL_MAX_CHWIDTH_20MHZ:
                phy_mode = BSAL_PHY_MODE_11NG_HT20;
            default:
                break;
        }
    }
    LOGD("%s: "PRI(os_macaddr_t)": phy_mode=%d",
        __func__, FMT(os_macaddr_t, data->mac_addr),
        phy_mode);
    return phy_mode;
}

static int sta_get_max_mcs_nss_capab(const char *ifname, const char *mac, bsal_cli_info *data)
{
    uint32_t ht_nss_max = 0;
    uint32_t ht_mcs_max = 0;
    uint32_t vht_nss_max = 0;
    uint32_t vht_mcs_max = 0;
    uint32_t he_nss_max = 0;
    uint32_t he_mcs_max = 0;
    uint32_t mcs_max = 0;
    uint32_t nss_max = 0;
    uint8_t he_mcs_count = 0;

    hostapd_sta_info_t sta;
    memset(&sta, 0, sizeof(hostapd_sta_info_t));

    hostapd_sta_info(ifname, mac, &sta);

    ht_nss_max = get_ht_nss_max(sta.ht_mcs_set);
    ht_mcs_max = get_ht_mcs_max(sta.ht_mcs_set);

    if (sta.vht_caps_info > 0) {
        vht_nss_max = get_vht_numstreams(sta.vht_rx_mcs_map);
        vht_mcs_max = get_vht_mcs_max(sta.vht_rx_mcs_map);
    }

    if (sta.he_capab_len > 0) {
        he_mcs_count = ieee80211_he_mcs_count(sta.he_phy_capab_info);
        he_nss_max = get_he_nss_max((uint16_t *)sta.he_capab_optional, he_mcs_count);
        he_mcs_max = get_he_mcs_max((uint16_t *)sta.he_capab_optional, he_mcs_count);
    }

    LOGD("%s: "PRI(os_macaddr_t)": ht_nss_max=%d, ht_mcs_max=%d, vht_mcs_max=%d, "
            "vht_nss_max=%d, he_mcs_max=%d, he_nss_max=%d",
            __func__, FMT(os_macaddr_t, data->mac_addr),
            ht_nss_max, ht_mcs_max, vht_mcs_max, vht_nss_max,
            he_mcs_max, he_nss_max);

    /* Max mcs x nss: */
    mcs_max = ht_mcs_max % 8;
    nss_max = ht_nss_max;
    if (vht_mcs_max > mcs_max)
        mcs_max = vht_mcs_max;
    if (vht_nss_max > nss_max)
        nss_max = vht_nss_max;
    if (he_mcs_max > mcs_max)
        mcs_max = he_mcs_max;
    if (he_nss_max > nss_max)
        nss_max = he_nss_max;

    data->datarate_info.max_chwidth = 0;
    data->datarate_info.max_streams = 0;
    data->datarate_info.max_MCS = 0;

    /* get max channel width */
    data->datarate_info.max_chwidth = get_max_chwidth(&sta);
    /* get phy_mode with max channel width */
    data->datarate_info.phy_mode = sta_get_phy_mode(data, &sta);
    data->datarate_info.max_MCS = mcs_max;
    data->datarate_info.max_streams = nss_max;

    LOGD("%s: "PRI(os_macaddr_t)": max_MCS=%d, max_streams=%d, max_chwidth=%d, phy_mode=%d",
        __func__, FMT(os_macaddr_t, data->mac_addr),
        data->datarate_info.max_MCS,  data->datarate_info.max_streams,
        data->datarate_info.max_chwidth, data->datarate_info.phy_mode);
    return 0;
}

/***************************************************************************************/

int32_t hextonum(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int hextobin(const char *hex, size_t h_len, uint8_t *binbuf, size_t *b_len)
{
    size_t i;
    int a;
    int b1;
    int b2;
    const char *h_pos = hex;
    uint8_t *b_pos = binbuf;
    *b_len = 0;

    for (i = 0; i < h_len; i++) {
        b1 = hextonum(*h_pos++);
        if (b1 < 0)
            return -1;
        b2 = hextonum(*h_pos++);
        if (b2 < 0)
            return -1;
        a = (b1 << 4) | b2;
        if (a < 0)
            return -1;
        *b_pos++ = a;
        (*b_len)++;
    }

    return 0;
}

int bintohex(const uint8_t *binbuf, size_t isize, char *hexbuf, size_t osize)
{
    char *p;
    size_t i;

    if (osize < (isize * 2 + 1))
        return -1;

    memset(hexbuf, 0, osize);
    p = &hexbuf[0];

    for (i = 0; i < isize; i++)
        p += sprintf(p, "%02hhx", binbuf[i]);

    return 0;
}

/***************************************************************************************/

static void bsal_add_client(bsal_cli_info *client)
{
    ds_dlist_insert_tail(&bsal_cli_info_list, client);
    LOGI("%s: Added client " PRI(os_macaddr_t), __func__, FMT(os_macaddr_pt, &client->mac_addr));
}

static void bsal_remove_client(bsal_cli_info *client)
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
    return SNR_NONE;
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

void bsal_cli_rssi_xing(struct ev_loop *loop, ev_timer *timer, int revents)
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

static void bsal_hapd_sta_disconnected(struct hapd *hapd, const char *in_buf)
{
    bsal_event_t event = { 0 };
    os_macaddr_t bssid;
    bsal_cli_info *client;
    char *parse_buf = strdupa(in_buf);

    event.type = BSAL_EVENT_CLIENT_DISCONNECT;

    STRSCPY(event.ifname, hapd->ctrl.bss);

    if (os_nif_macaddr_from_str(&bssid, parse_buf))
        memcpy(&event.data.disconnect.client_addr, &bssid, sizeof(event.data.disconnect.client_addr));

    event.data.disconnect.type = BSAL_DISC_TYPE_DISASSOC;

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


static void bsal_hapd_frame_disconnect(struct hapd *hapd, const char *in_buf)
{
    char         *kv;
    const char   *k;
    const char   *v;
    bsal_event_t event = { 0 };
    os_macaddr_t bssid;
    bsal_cli_info *client;
    char *parse_buf = strdupa(in_buf);

    event.type = BSAL_EVENT_CLIENT_DISCONNECT;

    STRSCPY(event.ifname, hapd->ctrl.bss);

    // NL80211-CMD-FRAME type=EVT_FRAME_DISCONNECT STA=40:b0:76:cf:b1:1a disconnect_type=deauth reason=1
    while ((kv = strsep(&parse_buf, " "))) {
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

static int bsal_process_assoc_req_frame(const char *ifname, const char *frame, int reassoc)
{
    uint8_t                 *buf;
    const uint8_t           *ies;
    size_t                  buf_len = 0;
    size_t                  ies_len = 0;
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
        return -1;

    hextobin(frame, strlen(frame), buf, &buf_len);

    mgmt = (struct ieee80211_mgmt *) buf;

    if (reassoc)
        fixed_param_len = IEEE80211_FIXED_PARAM_LEN_REASSOC;
    else
        fixed_param_len = IEEE80211_FIXED_PARAM_LEN_ASSOC;

    // TODO: use u.(re)assoc_req.variable instead of calculating ies position
    ies = ((const uint8_t *) buf) + IEEE80211_HDRLEN + fixed_param_len;
    ies_len = buf_len - IEEE80211_HDRLEN - fixed_param_len;
    if (ies_len <= 0)
        goto error;

    client = bsal_get_client(ifname, (os_macaddr_t *)mgmt->hdr.sa);
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
        LOGI("%s: received assoc ies length[%zd] exceeds buffer len[%zu]",
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
    char            *k;
    char            *v;
    uint8_t         *buf;
    char            *hex_buf = NULL;
    size_t          buf_len = 0;
    size_t          alloc_buf_size = 0;
    bsal_event_t    event;
    char            *parse_buf = strdupa(in_buf);

    memset(&event, 0, sizeof(event));

    while ((kv = strsep(&parse_buf, " "))) {
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
    char  *parse_buf = strdupa(buf);

    memset(&event, 0, sizeof(event));

    event.type = BSAL_EVENT_PROBE_REQ;

    STRSCPY(event.ifname, hapd->ctrl.bss);

    // NL80211-CMD-FRAME type=EVT-FRAME-PROBE-REQ sa=9a:00:80:9d:d4:66 ssi_signal=-79 ssid_null=1 blocked=1
    while ((kv = strsep(&parse_buf, " "))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "ssi_signal")) {
                event.data.probe_req.rssi = rssi_to_snr(&bsal_nl_global,
                                                        util_sys_ifname_to_idx(hapd->ctrl.bss),
                                                        atoi(v));
            }
            if (!strcmp(k, "ssid_null"))
                event.data.probe_req.ssid_null = atoi(v);
            if (!strcmp(k, "blocked"))
                event.data.probe_req.blocked = atoi(v);
            if (!strcmp(k, "sa"))
                if (os_nif_macaddr_from_str(&bssid, v))
                    memcpy(&event.data.probe_req.client_addr, &bssid, sizeof(event.data.probe_req.client_addr));
        }
    }

    LOGD("%s: bsal event.type:%d probe_req.rssi:%d probe_req.ssid_null:%d " PRI(os_macaddr_t),
         __func__, event.type, event.data.probe_req.rssi, event.data.probe_req.ssid_null,
         FMT(os_macaddr_t, *(os_macaddr_t *)event.data.probe_req.client_addr));

    _bsal_event_cb(&event);

    return;
}

static void bsal_hapd_retry_ctrl_cb(EV_P_ ev_timer *timer, int events) {
    struct bsal_hostap_ctrl_try *retry = container_of(timer, struct bsal_hostap_ctrl_try, timer);
    struct ctrl *ctrl = retry->ctrl;

    LOGD("%s: bsal retrying", ctrl->bss);

    if ((ctrl_request_ok(ctrl, "ATTACH osync_bm_rx_mgmt=1")) ||
        (++retry->retry_cnt == BSAL_HOSTAP_CTRL_MAX_RETRY)) {
        ev_timer_stop(EV_DEFAULT_ &retry->timer);
        FREE(retry);
        return;
    }

    ev_timer_again(EV_DEFAULT_ timer);
}

static void
bsal_hapd_ctrl_cb(struct ctrl *ctrl, int level, const char *buf, size_t len)
{
    struct hapd *hapd = container_of(ctrl, struct hapd, ctrl);
    const char *keyid = NULL;
    const char *pkhash = NULL;
    const char *event;
    const char *mac = NULL;
    const char *k;
    const char *v;
    const char *type = "";
    char *args = strdupa(buf);
    char *kv;

    event = strsep(&args, " ") ?: "_nope_";

    if (!strcmp(event, EV(NL_CMD_FRAME))) {
        while ((kv = strsep(&args, " "))) {
            if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
                if (!strcmp(k, "type")) {
                    type = v;
                    break;
                }
            }
        }
        if (!strcmp(type, EVT_FRAME_PROBE_REQ)) {
            bsal_hapd_frame_probe_req(hapd, args);
        } else if (!strcmp(type, EVT_FRAME_ACTION)) {
            bsal_hapd_frame_action(hapd, args);
        } else if (!strcmp(type, EVT_FRAME_DISCONNECT)) {
            bsal_hapd_frame_disconnect(hapd, args);
        } else {
            nl80211_cmd_frame_event(hapd, buf);
        }
    }

    if (!strcmp(event, EV(AP_STA_CONNECTED))) {
        mac = strsep(&args, " ") ?: "";

        while ((kv = strsep(&args, " "))) {
            if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
                if (!strcmp(k, "keyid"))
                    keyid = v;
                if (!strcmp(k, "dpp_pkhash"))
                    pkhash = v;
            }
        }

        LOGI("%s: %s: connected keyid=%s pkhash=%s", hapd->ctrl.bss, mac, keyid ?: "", pkhash ?: "");
        if (hapd->sta_connected)
            hapd->sta_connected(hapd, mac, keyid);

        return;
    }

    if (!strcmp(event, EV(AP_STA_DISCONNECTED)))
    {
        bsal_hapd_sta_disconnected(hapd, args);
    }


    LOGD("%s: event: <%d> %s", ctrl->bss, level, buf);

    if (!strncmp(buf, WPA_EVENT_TERMINATING, strlen(WPA_EVENT_TERMINATING))) {
        struct bsal_hostap_ctrl_try *try = calloc(1, sizeof(struct bsal_hostap_ctrl_try));
        if (try) {
            try->ctrl = ctrl;
            ev_timer_init(&try->timer, bsal_hapd_retry_ctrl_cb, 0., 5.);
            ev_timer_again(EV_DEFAULT_ &try->timer);
        }
    }
}

static bool is_onewifi_enabled()
{
    // equivalent to: ovsh s Node_Services -w service==owm status
    // positive case output: status | enabled |
    json_t *owm_rows = ovsdb_sync_select("Node_Services", "service", "owm");
    json_t *owm_status = json_object_get(json_array_get(owm_rows, 0), "status");
    const char *status_value = json_string_value(owm_status);
    if ((status_value == NULL) || (strcmp(status_value, "enabled") != 0)) {
        return false;
    } else {
        return true;
    }
}

static int hostap_init_bss(const char *bss)
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

    if (!is_onewifi_enabled())
        hapd->sta_connected = bsal_hapd_sta_connected;
    if (kconfig_enabled(CONFIG_PLATFORM_IS_MTK))
        hapd->ctrl.cb = bsal_hapd_ctrl_cb;

#ifndef CONFIG_PLATFORM_IS_MTK
    hapd->cmd_frame = nl80211_cmd_frame_event;
    hapd->cmd_frame_probe_req = bsal_hapd_frame_probe_req;
    hapd->cmd_frame_action = bsal_hapd_frame_action;
    hapd->cmd_frame_disconnect = bsal_hapd_frame_disconnect;
#endif

    if (!ctrl_enable(&hapd->ctrl)) {
        LOGI("%s: bsal hapd initialized for %s", __func__, bss);
        /* Enbale osync_bm_rx_mgmt so that hapd allow send rx_mgmt NL_CMD_FRAME events */
        WARN_ON(!ctrl_request_ok(&hapd->ctrl, "ATTACH osync_bm_rx_mgmt=1"));
    }

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
#ifdef CONFIG_PLATFORM_IS_MTK
    if (!hostapd_deny_acl_update(ifname, mac_addr, add, false)) {
        LOGN("Failed to update MAC ACL list");
        return -1;
    }
#else
    if (!hostapd_deny_acl_update(ifname, mac_addr, add)) {
        LOGN("Failed to update MAC ACL list");
        return -1;
    }
#endif

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

    client = bsal_get_client(ifname, (os_macaddr_t *)mac_addr);
    if (client) {
        client->snr_lwm_xing = conf->rssi_low_xing;
        client->snr_hwm_xing = conf->rssi_high_xing;
        LOGT("%s: station "PRI(os_macaddr_t)" - xing low=%d high=%d updated",
             __func__, FMT(os_macaddr_t, client->mac_addr),
             client->snr_lwm_xing, client->snr_hwm_xing);
    }

    // Blacklist station if not connected and HWM == 1
    if (conf->rssi_probe_hwm == BM_CLIENT_MAGIC_HWM) {
        if (!client->connected || kconfig_enabled(CONFIG_PLATFORM_IS_MTK))
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
    bsal_cli_info *client;

    client = bsal_get_client(ifname, (os_macaddr_t *)mac_addr);
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

    if ((client = bsal_get_client(ifname, (os_macaddr_t *)mac_addr)))
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
    bsal_cli_info *client = bsal_get_client(ifname, (os_macaddr_t *)mac_addr);

    if (!client) {
        info->connected = false;
        return -1;
    }
    char sta_mac[MACADDR_STR_LEN] = {'\0'};
    memset(info, 0, sizeof(bsal_client_info_t));

    info->is_BTM_supported = client->is_BTM_supported;
    info->is_RRM_supported = client->is_RRM_supported;

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

    /* get nss and mcs */
    mac_dump(sta_mac, mac_addr);
    sta_get_max_mcs_nss_capab(ifname, sta_mac, client);

    info->datarate_info.phy_mode = client->datarate_info.phy_mode;
    info->datarate_info.max_chwidth = client->datarate_info.max_chwidth;
    info->datarate_info.max_streams = client->datarate_info.max_streams;
    info->datarate_info.max_MCS = client->datarate_info.max_MCS;

    LOGD("%s: station=" PRI(os_macaddr_t)
         " rssi[%d] snr[%d]"
         " max_chwidth[%d] max_streams[%d]"
         " max_MCS[%d] phy_mode[%d]"
         " tx_bytes[%"PRIu64"] rx_bytes[%"PRIu64"]",
         __func__,
         FMT(os_macaddr_t, client->mac_addr),
         client->rssi,
         client->snr,
         client->datarate_info.max_chwidth,
         client->datarate_info.max_streams,
         client->datarate_info.max_MCS,
         client->datarate_info.phy_mode,
         client->tx_bytes,
         client->rx_bytes);

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

        STRSCAT(neigh_list, cmd);
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
             (uint8_t)(strlen(hex_ssid)/2),
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
