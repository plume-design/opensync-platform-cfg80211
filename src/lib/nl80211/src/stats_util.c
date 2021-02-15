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
#include <string.h>

#include <linux/nl80211.h>
#include <linux/if_ether.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/genl/family.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "nl80211.h"
#include "stats_nl80211.h"

struct nl_global_info nl_sm_global;
static ev_io nl_sm_loop;
struct nl80211_scan {
    char name[IF_NAMESIZE];
    target_scan_cb_t *scan_cb;
    void *scan_ctx;
    struct avl_node avl;
    ev_async async;
};

static struct avl_tree nl80211_scan_tree = AVL_TREE_INIT(nl80211_scan_tree, avl_strcmp, false, NULL);

static int nl80211_txchainmask_recv(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    unsigned int *mask = (unsigned int *)arg;

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_WIPHY_ANTENNA_TX])
        *mask = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_TX]);

    return NL_OK;
}

int nl80211_get_tx_chainmask(char *ifname, unsigned int *mask)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return false;

    msg = nlmsg_init(&nl_sm_global, NL80211_CMD_GET_WIPHY, false);
    if (!msg) {
        return false;
    }

    nla_put_u32(msg, NL80211_ATTR_WIPHY, if_index);
    return nlmsg_send_and_recv(&nl_sm_global, msg, nl80211_txchainmask_recv, mask);
}

static int nl80211_interface_recv(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nl_call_param *nl_call_param = (struct nl_call_param *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    ssid_list_t *ssid_entry = NULL;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_SSID] && tb[NL80211_ATTR_IFNAME]) {
        ssid_entry = malloc(sizeof(ssid_list_t));
        strncpy(ssid_entry->ssid, nla_data(tb[NL80211_ATTR_SSID]), sizeof(ssid_entry->ssid));
        strncpy(ssid_entry->ifname, nla_data(tb[NL80211_ATTR_IFNAME]), sizeof(ssid_entry->ifname));
        ds_dlist_insert_tail(nl_call_param->list, ssid_entry);
    }
    return NL_OK;
}

static target_client_record_t* target_client_record_alloc()
{
    target_client_record_t *record = NULL;

    record = malloc(sizeof(target_client_record_t));
    if (record == NULL)
        return NULL;

    memset(record, 0, sizeof(target_client_record_t));

    return record;
}

static int nl80211_assoclist_recv(struct nl_msg *msg, void *arg)
{
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32    },
        [NL80211_STA_INFO_RX_PACKETS]    = { .type = NLA_U32    },
        [NL80211_STA_INFO_TX_PACKETS]    = { .type = NLA_U32    },
        [NL80211_STA_INFO_RX_BITRATE]    = { .type = NLA_NESTED },
        [NL80211_STA_INFO_TX_BITRATE]    = { .type = NLA_NESTED },
        [NL80211_STA_INFO_SIGNAL]        = { .type = NLA_U8     },
        [NL80211_STA_INFO_RX_BYTES]      = { .type = NLA_U32    },
        [NL80211_STA_INFO_TX_BYTES]      = { .type = NLA_U32    },
        [NL80211_STA_INFO_TX_RETRIES]    = { .type = NLA_U32    },
        [NL80211_STA_INFO_TX_FAILED]     = { .type = NLA_U32    },
        [NL80211_STA_INFO_RX_DROP_MISC]  = { .type = NLA_U64    },
        [NL80211_STA_INFO_T_OFFSET]      = { .type = NLA_U64    },
        [NL80211_STA_INFO_STA_FLAGS] =
                { .minlen = sizeof(struct nl80211_sta_flag_update) },
    };
    static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
        [NL80211_RATE_INFO_BITRATE]      = { .type = NLA_U16    },
        [NL80211_RATE_INFO_MCS]          = { .type = NLA_U8     },
        [NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG   },
        [NL80211_RATE_INFO_SHORT_GI]     = { .type = NLA_FLAG   },
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nl_call_param *nl_call_param = (struct nl_call_param *)arg;
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    target_client_record_t *client_entry;

    memset(tb, 0, sizeof(tb));
    memset(sinfo, 0, sizeof(sinfo));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);
    if (!tb[NL80211_ATTR_MAC]) {
        return NL_OK;
    }

    if (!tb[NL80211_ATTR_STA_INFO] ||
               nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                   tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        LOGE("%s: invalid assoc entry", nl_call_param->ifname);
        return NL_OK;
    }
    client_entry = target_client_record_alloc();
    client_entry->info.type = nl_call_param->type;
    memcpy(client_entry->info.mac, nla_data(tb[NL80211_ATTR_MAC]), ETH_ALEN);
#if 0
    // TODO - Need to check how to map ioctll structures.
    if (sinfo[NL80211_STA_INFO_TX_BYTES])
        client_entry->stats.client.bytes_tx = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);
    if (sinfo[NL80211_STA_INFO_RX_BYTES])
        client_entry->stats.client.bytes_rx = nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);
    if (sinfo[NL80211_STA_INFO_RX_BITRATE] &&
            !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE],
                              rate_policy)) {
        if (rinfo[NL80211_RATE_INFO_BITRATE32])
            client_entry->stats.client.rate_rx = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]) * 100;
        else if (rinfo[NL80211_RATE_INFO_BITRATE])
            client_entry->stats.client.rate_rx = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE]) * 100;
    }
    if (sinfo[NL80211_STA_INFO_TX_BITRATE] &&
            !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE],
                              rate_policy)) {
        if (rinfo[NL80211_RATE_INFO_BITRATE32])
            client_entry->stats.client.rate_tx = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]) * 100;
        else if (rinfo[NL80211_RATE_INFO_BITRATE])
            client_entry->stats.client.rate_tx = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE]) * 100;
    }
    if (sinfo[NL80211_STA_INFO_SIGNAL])
        client_entry->stats.client.rssi = (signed char)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
    if (sinfo[NL80211_STA_INFO_TX_PACKETS])
        client_entry->stats.client.frames_tx = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]);
    if (sinfo[NL80211_STA_INFO_RX_PACKETS])
        client_entry->stats.client.frames_rx = nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]);
    if (sinfo[NL80211_STA_INFO_TX_RETRIES])
        client_entry->stats.client.retries_tx = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);
    if (sinfo[NL80211_STA_INFO_TX_FAILED])
        client_entry->stats.client.errors_tx = nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);
    if (sinfo[NL80211_STA_INFO_RX_DROP_MISC])
        client_entry->stats.client.errors_rx = nla_get_u64(sinfo[NL80211_STA_INFO_RX_DROP_MISC]);
#else
    if (sinfo[NL80211_STA_INFO_TX_BYTES])
        client_entry->stats.bytes_tx = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);
    if (sinfo[NL80211_STA_INFO_RX_BYTES])
        client_entry->stats.bytes_rx = nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);
    if (sinfo[NL80211_STA_INFO_RX_BITRATE] &&
            !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE],
                              rate_policy)) {
        if (rinfo[NL80211_RATE_INFO_BITRATE32])
            client_entry->stats.rate_rx = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]) * 100;
        else if (rinfo[NL80211_RATE_INFO_BITRATE])
            client_entry->stats.rate_rx = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE]) * 100;
    }
    if (sinfo[NL80211_STA_INFO_TX_BITRATE] &&
            !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE],
                              rate_policy)) {
        if (rinfo[NL80211_RATE_INFO_BITRATE32])
            client_entry->stats.rate_tx = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]) * 100;
        else if (rinfo[NL80211_RATE_INFO_BITRATE])
            client_entry->stats.rate_tx = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE]) * 100;
    }
    if (sinfo[NL80211_STA_INFO_SIGNAL])
        client_entry->stats.rssi = (signed char)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
    if (sinfo[NL80211_STA_INFO_TX_PACKETS])
        client_entry->stats.frames_tx = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]);
    if (sinfo[NL80211_STA_INFO_RX_PACKETS])
        client_entry->stats.frames_rx = nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]);
    if (sinfo[NL80211_STA_INFO_TX_RETRIES])
        client_entry->stats.retries_tx = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);
    if (sinfo[NL80211_STA_INFO_TX_FAILED])
        client_entry->stats.errors_tx = nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);
    if (sinfo[NL80211_STA_INFO_RX_DROP_MISC])
        client_entry->stats.errors_rx = nla_get_u64(sinfo[NL80211_STA_INFO_RX_DROP_MISC]);
#endif
    ds_dlist_insert_tail(nl_call_param->list, client_entry);

    return NL_OK;
}

static target_survey_record_t* target_survey_record_alloc()
{
    target_survey_record_t *record = NULL;

    record = malloc(sizeof(target_survey_record_t));
    if (record == NULL)
        return NULL;

    memset(record, 0, sizeof(target_survey_record_t));

    return record;
}

static int nl80211_survey_recv(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nl_call_param *nl_call_param = (struct nl_call_param *)arg;
    struct nlattr *si[NL80211_SURVEY_INFO_MAX + 1];
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    static struct nla_policy sp[NL80211_SURVEY_INFO_MAX + 1] = {
        [NL80211_SURVEY_INFO_FREQUENCY]         = { .type = NLA_U32 },
        [NL80211_SURVEY_INFO_TIME]              = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_TX]           = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_RX]           = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_BUSY]         = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_EXT_BUSY]     = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_SCAN]         = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_NOISE]             = { .type = NLA_U8 },
    };
    target_survey_record_t  *survey_record;

    memset(tb, 0, sizeof(tb));
    memset(si, 0, sizeof(si));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_SURVEY_INFO])
        return NL_OK;

    if (nla_parse_nested(si, NL80211_SURVEY_INFO_MAX,
                     tb[NL80211_ATTR_SURVEY_INFO], sp))
        return NL_SKIP;

    survey_record = target_survey_record_alloc();

    if (si[NL80211_SURVEY_INFO_FREQUENCY])
        survey_record->info.chan = util_freq_to_chan(
                                        nla_get_u32(si[NL80211_SURVEY_INFO_FREQUENCY]));

    if (si[NL80211_SURVEY_INFO_TIME_RX])
        survey_record->chan_self = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_RX]);

    if (si[NL80211_SURVEY_INFO_TIME_TX])
        survey_record->chan_tx = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_TX]);

    if (si[NL80211_SURVEY_INFO_TIME_RX])
        survey_record->chan_rx = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_RX]);

    if (si[NL80211_SURVEY_INFO_TIME_BUSY])
        survey_record->chan_busy = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_BUSY]);

    if (si[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
        survey_record->chan_busy_ext = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);

    if (si[NL80211_SURVEY_INFO_TIME])
        survey_record->duration_ms = nla_get_u64(si[NL80211_SURVEY_INFO_TIME]);

    if (si[NL80211_SURVEY_INFO_NOISE])
        survey_record->chan_noise = nla_get_u8(si[NL80211_SURVEY_INFO_NOISE]);

    ds_dlist_insert_tail(nl_call_param->list, survey_record);

    return NL_OK;
}


int nl80211_get_ssid(struct nl_call_param *nl_call_param)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(nl_call_param->ifname)) < 0)
        return false;

    msg = nlmsg_init(&nl_sm_global, NL80211_CMD_GET_INTERFACE, true);
    if (!msg) {
        return false;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    return nlmsg_send_and_recv(&nl_sm_global, msg, nl80211_interface_recv, nl_call_param);
}

int nl80211_get_assoclist(struct nl_call_param *nl_call_param)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(nl_call_param->ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(&nl_sm_global, NL80211_CMD_GET_STATION, true);
    if (!msg) {
        return -EINVAL;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nlmsg_send_and_recv(&nl_sm_global, msg, nl80211_assoclist_recv, nl_call_param);
    return 0;
}

int nl80211_get_survey(struct nl_call_param *nl_call_param)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(nl_call_param->ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(&nl_sm_global, NL80211_CMD_GET_SURVEY, true);
    if (!msg) {
        return -EINVAL;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nlmsg_send_and_recv(&nl_sm_global, msg, nl80211_survey_recv, nl_call_param);
    return 0;
}

static int nl80211_scan_trigger_recv(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

static int nl80211_scan_add(char *name, target_scan_cb_t *scan_cb, void *scan_ctx)
{
    struct nl80211_scan *nl80211_scan = avl_find_element(&nl80211_scan_tree, name, nl80211_scan, avl);

    if (!nl80211_scan) {
        nl80211_scan = malloc(sizeof(*nl80211_scan));
        if (!nl80211_scan)
            return -EINVAL;
        memset(nl80211_scan, 0, sizeof(*nl80211_scan));
        strncpy(nl80211_scan->name, name, IF_NAMESIZE);
        nl80211_scan->avl.key = nl80211_scan->name;
        avl_insert(&nl80211_scan_tree, &nl80211_scan->avl);
        LOGT("%s: added scan context", name);
    }

    nl80211_scan->scan_cb = scan_cb;
    nl80211_scan->scan_ctx = scan_ctx;
    return 0;
}

int nl80211_scan_trigger(char *ifname, uint32_t *chan_list, uint32_t chan_num,
                         int dwell_time, radio_scan_type_t scan_type,
                         target_scan_cb_t *scan_cb, void *scan_ctx)
{
    int if_index;
    struct nl_msg *msg;
    struct nlattr *freq;
    unsigned int i;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(&nl_sm_global, NL80211_CMD_TRIGGER_SCAN, false);
    if (!msg)
        return -EINVAL;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    LOGT("%s: not setting dwell time\n", ifname);
    //nla_put_u16(msg, NL80211_ATTR_MEASUREMENT_DURATION, dwell_time);
    freq = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
    for (i = 0; i < chan_num; i++)
         nla_put_u32(msg, i, util_chan_to_freq(chan_list[i]));
    nla_nest_end(msg, freq);

    if (nl80211_scan_add(ifname, scan_cb, scan_ctx))
        return false;

    nlmsg_send_and_recv(&nl_sm_global, msg, nl80211_scan_trigger_recv, NULL);
    return 0;
}

static void nl80211_scan_del(struct nl80211_scan *nl80211_scan)
{
    LOGT("%s: delete scan context", nl80211_scan->name);
    ev_async_stop(EV_DEFAULT, &nl80211_scan->async);
    avl_delete(&nl80211_scan_tree, &nl80211_scan->avl);
    free(nl80211_scan);
}

struct nl80211_scan *nl80211_scan_find(const char *name)
{
    struct nl80211_scan *nl80211_scan = avl_find_element(&nl80211_scan_tree, name, nl80211_scan, avl);

    if (!nl80211_scan)
        LOGN("%s: scan context does not exist", name);

    return nl80211_scan;
}

static int nl80211_scan_abort_recv(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

int nl80211_scan_abort(char *ifname)
{
    int if_index;
    struct nl_msg *msg;
    struct nl80211_scan *nl80211_scan;

    nl80211_scan = nl80211_scan_find(ifname);
    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(&nl_sm_global, NL80211_CMD_ABORT_SCAN, false);
    if (!msg) {
        return -EINVAL;
    }
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    if (nl80211_scan)
        nl80211_scan_del(nl80211_scan);

    return nlmsg_send_and_recv(&nl_sm_global, msg, nl80211_scan_abort_recv, NULL);
}

static int nl80211_scan_dump_recv(struct nl_msg *msg, void *arg)
{
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_TSF]                  = { .type = NLA_U64 },
        [NL80211_BSS_FREQUENCY]            = { .type = NLA_U32 },
        [NL80211_BSS_BSSID]                = { 0 },
        [NL80211_BSS_BEACON_INTERVAL]      = { .type = NLA_U16 },
        [NL80211_BSS_CAPABILITY]           = { .type = NLA_U16 },
        [NL80211_BSS_INFORMATION_ELEMENTS] = { 0 },
        [NL80211_BSS_SIGNAL_MBM]           = { .type = NLA_U32 },
        [NL80211_BSS_SIGNAL_UNSPEC]        = { .type = NLA_U8  },
        [NL80211_BSS_STATUS]               = { .type = NLA_U32 },
        [NL80211_BSS_SEEN_MS_AGO]          = { .type = NLA_U32 },
        [NL80211_BSS_BEACON_IES]           = { 0 },
    };
    struct nl_call_param *nl_call_param = (struct nl_call_param *)arg;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    dpp_neighbor_record_list_t *neighbor;

    memset(tb, 0, sizeof(tb));
    memset(bss, 0, sizeof(bss));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_BSS] ||
            nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy) ||
            !bss[NL80211_BSS_BSSID])
        return NL_OK;

    neighbor = dpp_neighbor_record_alloc();
    neighbor->entry.type = nl_call_param->type;
    if (bss[NL80211_BSS_TSF])
        neighbor->entry.tsf = nla_get_u64(bss[NL80211_BSS_TSF]);
    if (bss[NL80211_BSS_FREQUENCY])
        neighbor->entry.chan =
                    util_freq_to_chan((int)nla_get_u32(bss[NL80211_BSS_FREQUENCY]));
    if (bss[NL80211_BSS_SIGNAL_MBM])
        neighbor->entry.sig = ((int) nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM])) / 100;
    if (bss[NL80211_BSS_SEEN_MS_AGO])
        neighbor->entry.lastseen = nla_get_u32(bss[NL80211_BSS_SEEN_MS_AGO]);
    if (bss[NL80211_BSS_BSSID]) {
        mac_dump(neighbor->entry.bssid, nla_data(bss[NL80211_BSS_BSSID]));
        LOGT("Parsed %s BSSID %s",
             radio_get_name_from_type(nl_call_param->type),neighbor->entry.bssid);
    }

    if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        int bssielen = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        unsigned char *bssie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        int len;

        while (bssielen >= 2 && bssielen >= bssie[1]) {
            switch (bssie[0]) {
            case 0: /* SSID */
            case 114: /* Mesh ID */
                len = min(bssie[1], 32 + 1);
                memcpy(neighbor->entry.ssid, bssie + 2, len);
                neighbor->entry.ssid[len] = 0;
                break;
            }
        bssielen -= bssie[1] + 2;
        bssie += bssie[1] + 2;
        }
    }
    LOGT("Parsed %s SSID %s",
         radio_get_name_from_type(nl_call_param->type), neighbor->entry.ssid);

    ds_dlist_insert_tail(nl_call_param->list, neighbor);
    return NL_OK;
}

int nl80211_scan_dump(struct nl_call_param *nl_call_param)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(nl_call_param->ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(&nl_sm_global, NL80211_CMD_GET_SCAN, true);
    if (!msg) {
        return -EINVAL;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    return nlmsg_send_and_recv(&nl_sm_global, msg, nl80211_scan_dump_recv, nl_call_param);
}

static void nl80211_scan_finish(char *name, bool state)
{
    struct nl80211_scan *nl80211_scan = nl80211_scan_find(name);

    if (nl80211_scan) {
        LOGN("%s: calling context cb", nl80211_scan->name);
        (*nl80211_scan->scan_cb)(nl80211_scan->scan_ctx, state);
        nl80211_scan_del(nl80211_scan);
    }
}

static int nl_event_parse(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    char ifname[IFNAMSIZ] = {'\0'};
    char phyname[IFNAMSIZ] = {'\0'};
    int ifidx = -1, phy = -1;

    memset(tb, 0, sizeof(tb));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFINDEX]) {
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
        if_indextoname(ifidx, ifname);
    } else if (tb[NL80211_ATTR_IFNAME]) {
        strncpy(ifname, nla_get_string(tb[NL80211_ATTR_IFNAME]), IFNAMSIZ);
    }

    if (tb[NL80211_ATTR_WIPHY]) {
        phy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
        if (tb[NL80211_ATTR_WIPHY_NAME])
            strncpy(phyname, nla_get_string(tb[NL80211_ATTR_WIPHY_NAME]), IFNAMSIZ);
        else
            snprintf(phyname, sizeof(phyname), "phy%d", phy);
    }

    switch (gnlh->cmd) {
        case NL80211_CMD_TRIGGER_SCAN:
            LOGN("%s: scan started\n", ifname);
            break;
        case NL80211_CMD_SCAN_ABORTED:
            LOGN("%s: scan aborted\n", ifname);
            nl80211_scan_finish(ifname, false);
            break;
        case NL80211_CMD_NEW_SCAN_RESULTS:
            LOGN("%s: scan completed\n", ifname);
            nl80211_scan_finish(ifname, true);
            break;
        default:
            break;
    }
    return NL_OK;
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

static void sm_nl_ev_handler(struct ev_loop *ev, struct ev_io *io, int event)
{
    int res = -EINVAL;

    nl_cb_err(nl_sm_global.nl_cb, NL_CB_CUSTOM, err_handler, NULL);
    nl_cb_set(nl_sm_global.nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);
    nl_cb_set(nl_sm_global.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(nl_sm_global.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl_event_parse, NULL);

    res = nl_recvmsgs(nl_sm_global.nl_evt_handle, nl_sm_global.nl_cb);
    if (res < 0)
        LOGE("Failed to receive event message");
}

int sm_nl_global_init(struct ev_loop *sm_evloop)
{
    if (netlink_init(&nl_sm_global) < 0) {
        LOGE("nl80211: failed to connect\n");
        return -1;
    }

    if (!sm_evloop)
        return -1;

    add_mcast_subscription(&nl_sm_global, "scan");

    ev_io_init(&nl_sm_loop, sm_nl_ev_handler, nl_socket_get_fd(nl_sm_global.nl_evt_handle), EV_READ);
    ev_io_start(sm_evloop, &nl_sm_loop);

    return 0;
}

int sm_stats_nl80211_init(void)
{
    struct ev_loop *sm_evloop = EV_DEFAULT;
    if (sm_nl_global_init(sm_evloop) < 0) {
        LOGN("failed to spawn nl80211");
        return -1;
    }
    return 0;
}
