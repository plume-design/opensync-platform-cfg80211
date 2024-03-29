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

#ifndef NL80211_H_INCLUDED
#define NL80211_H_INCLUDED

#include <string.h>
#include <inttypes.h>
#include "ds_dlist.h"
#include <ev.h>
#include "log.h"

#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <errno.h>
#include "util.h"
#include "log.h"
#include "os_common.h"
#include "dpp_types.h"
#include "dpp_neighbor.h"

#include "bsal.h"

#define MAC_ADDR_LEN 6
#define SSID_MAX_LEN 32

#define STATS_DELTA(n, o) ((n) < (o) ? (n) : (n) - (o))
#define PERCENT(v1, v2) (v2 > 0 ? (v1*100/v2) : 0)
#define min(a,b) (((a) < (b)) ? (a) : (b))

#define IEEE80211_CHAN_MAX  (196 + 1)

#define DEFAULT_NOISE_FLOOR (-95)

#define HT_CAP_SHORT_GI_20     BIT(5)
#define HT_CAP_SHORT_GI_40     BIT(6)
#define VHT_CAP_SHORT_GI_80    BIT(5)
#define VHT_CAP_SHORT_GI_160   BIT(6)
#define VHT_CAP_NO_BW_160      0x00
#define VHT_CAP_ONLY_BW_160    0x01
#define VHT_CAP_BW160_BW80P80  0x02

enum channel_state {
    INVALID,
    ALLOWED,
    CAC_STARTED,
    CAC_COMPLETED,
    NOP_STARTED,
    NOP_FINISHED,
};

struct channel_status {
    enum channel_state state;
};

struct nl_global_info {
    struct nl_cb *nl_cb;
    struct nl_sock *nl_msg_handle;
    struct nl_sock *nl_evt_handle;
    int nl_id;
};

struct mcast_group_id {
    char *name;
    int id;
};

struct data_buffer_4k {
    char buf[BFR_SIZE_4K];
    uint16_t len;
};

struct nl_call_param {
        char *ifname;
        radio_type_t type;
        ds_dlist_t *list;
};

typedef struct ssid_list {
        char ssid[RADIO_ESSID_LEN+1];
        char ifname[RADIO_NAME_LEN+1];
        ds_dlist_node_t node;
} ssid_list_t;

struct noise_info {
    int chan;
    int noise;
};

void netlink_deinit(struct nl_global_info *);

int add_mcast_subscription(struct nl_global_info *nl_global, char *name);

int nlmsg_send_and_recv(struct nl_global_info *nl_global,
                        struct nl_msg *msg,
                        int (*handler) (struct nl_msg *, void *),
                        void *arg);

struct nl_msg *nlmsg_init(struct nl_global_info *nl_global, int cmd, int dump);

int netlink_init(struct nl_global_info *nl_global);

void mac_dump(char *mac_addr, const unsigned char *arg);

int util_sys_ifname_to_idx(const char *ifname);

int util_sys_phyname_to_idx(const char *phyname);

int util_freq_to_chan(int freq);

int util_chan_to_freq(int freq);

int util_chan_to_freq_6g(int freq);

int mode_to_nl80211_attr_iftype(const char *mode, enum nl80211_iftype *type);

int util_ht_mode(enum nl80211_chan_width chanwidth, char *ht_mode, int len);

bool util_mode(enum nl80211_iftype type, char *mode, int len);

int util_get_temp_info(const char *ifname);

int nl_sm_init(struct ev_loop *sm_evloop);

int nl_req_get_iface_curr_chan(struct nl_global_info *nl_global, int if_index);

int nl_req_get_sta_rssi(
        struct nl_global_info *bsal_nl_global,
        const char *ifname,
        const uint8_t *mac_addr,
        int8_t *rssi
);

int rssi_to_snr(struct nl_global_info *nl_global, int if_idx, int rssi);

int nl_req_get_sta_info(
        struct nl_global_info *bsal_nl_global,
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_cli_info *data
);

int nl_req_get_ssid(struct nl_global_info *bsal_nl_global, const char *ifname, char *ssid);

bool nl_req_get_mode(struct nl_global_info *nl_global, const char *ifname, char *mode, int len);

int nl_req_set_txpwr(struct nl_global_info *nl_global, const char *ifname, const int dbm);

int nl_req_get_txpwr(struct nl_global_info *nl_global, const char *ifname);

int nl_req_get_antenna(struct nl_global_info *nl_global, const char *ifname,
                       int *avail_tx_antenna, int *avail_rx_antenna,
                       int *tx_antenna, int *rx_antenna);

int nl_req_set_antenna(struct nl_global_info *nl_global, const char *ifname,
                       const int tx_antenna, const int rx_antenna);

int nl_req_get_channels(
        struct nl_global_info *nl_global,
        const char *ifname,
        char *buf,
        int len
);

bool nl_req_get_ht_mode(
        struct nl_global_info *nl_global,
        const char *ifname,
        char *ht_mode,
        int len
);

int nl_req_get_reg_dom(struct nl_global_info *nl_global, char *buf);

int nl_req_init_channels(
        struct nl_global_info *nl_global,
        const char *ifname,
        struct channel_status *chan_status
);

int nl_req_del_iface(struct nl_global_info *nl_global, const char *ifname);

int nl_req_add_iface(
        struct nl_global_info *nl_global,
        const char *new_vif_name,
        const char *r_ifname,
        const char *mode,
        char *mac_addr
);

int nl_req_get_iface_supp_band(struct nl_global_info *nl_global, const char *ifname);

int nl_req_get_iface_ht_capa(struct nl_global_info *nl_global, const char *ifname);

int nl_req_get_iface_vht_capa(struct nl_global_info *nl_global, const char *ifname);

int netlink_wm_init(struct nl_global_info *nl_global);

int util_get_curr_chan_noise(struct nl_global_info *nl_global, int if_idx, int channel);

#endif /* NL80211_H_INCLUDED */
