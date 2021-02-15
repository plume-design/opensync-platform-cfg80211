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

#include "ds_dlist.h"
#include <ev.h>
#include "log.h"

#include <libubox/avl-cmp.h>
#include <libubox/avl.h>
#include <libubox/vlist.h>

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

#define MAC_ADDR_LEN 6
#define SSID_MAX_LEN 32

#define PERCENT(v1, v2) (v2 > 0 ? (v1*100/v2) : 0)
#define min(a,b) (((a) < (b)) ? (a) : (b))

#define IEEE80211_CHAN_MAX  (196 + 1)

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

typedef bool target_stats_clients_cb_t (
        ds_dlist_t                 *client_list,
        void                       *ctx,
        int                         status);

typedef bool target_stats_survey_cb_t (
        ds_dlist_t                 *survey_list,
        void                       *survey_ctx,
        int                         status);

typedef bool target_scan_cb_t(
        void                       *scan_ctx,
        int                         status);

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
int mode_to_nl80211_attr_iftype(const char *mode, enum nl80211_iftype *type);
int util_ht_mode(enum nl80211_chan_width chanwidth, char *ht_mode, int len);
bool util_mode(enum nl80211_iftype type, char *mode, int len);
int util_get_temp_info(const char *ifname);
extern int nl80211_get_tx_chainmask(char *name, unsigned int *mask);
extern int nl80211_get_ssid(struct nl_call_param *nl_call_param);
extern int nl80211_get_assoclist(struct nl_call_param *nl_call_param);
extern int nl80211_get_survey(struct nl_call_param *nl_call_param);
extern int nl80211_scan_trigger(char *, uint32_t *, uint32_t,
                                int, radio_scan_type_t,
                                target_scan_cb_t *, void *);
extern int nl80211_scan_abort(char *);
extern int nl80211_scan_dump(struct nl_call_param *nl_call_param);
int sm_stats_nl80211_init(void);

#endif /* NL80211_H_INCLUDED */
