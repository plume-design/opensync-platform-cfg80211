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
#include "nl80211.h"
#include "nl80211_stats.h"
#include "target_nl80211.h"
#include <string.h>

#include <ev.h>
#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

static struct avl_tree nl80211_scan_tree = AVL_TREE_INIT(nl80211_scan_tree, avl_strcmp, false, NULL);

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
        STRSCPY(nl80211_scan->name, name);
        nl80211_scan->avl.key = nl80211_scan->name;
        avl_insert(&nl80211_scan_tree, &nl80211_scan->avl);
        LOGT("%s: added scan context", name);
    }

    nl80211_scan->scan_cb = scan_cb;
    nl80211_scan->scan_ctx = scan_ctx;
    return 0;
}

int nl80211_scan_trigger(struct nl_global_info *nl_sm_global,
                         char *ifname, uint32_t *chan_list, uint32_t chan_num,
                         int dwell_time, radio_scan_type_t scan_type,
                         target_scan_cb_t *scan_cb, void *scan_ctx)
{
    int if_index;
    struct nl_msg *msg;
    struct nlattr *freq;
    unsigned int i;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_TRIGGER_SCAN, false);
    if (!msg)
        return -EINVAL;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    LOGT("%s: not setting dwell time\n", ifname);
    freq = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
    for (i = 0; i < chan_num; i++)
         nla_put_u32(msg, i, util_chan_to_freq(chan_list[i]));
    nla_nest_end(msg, freq);

    if (nl80211_scan_add(ifname, scan_cb, scan_ctx))
        return false;

    nlmsg_send_and_recv(nl_sm_global, msg, nl80211_scan_trigger_recv, NULL);
    return 0;
}

bool nl80211_stats_scan_start(struct nl_global_info *nl_sm_global,
	        	      radio_entry_t *radio_cfg, uint32_t *chan_list,
                              uint32_t chan_num, radio_scan_type_t scan_type,
                              int32_t dwell_time, target_scan_cb_t *scan_cb,
                              void *scan_ctx)
{
    char *ifname = radio_cfg->if_name;
    bool ret = true;

    if (nl80211_scan_trigger(nl_sm_global, ifname, chan_list, chan_num,
                                dwell_time, scan_type, scan_cb, scan_ctx) < 0)
        ret = false;
    LOGT("%s: scan trigger returned %d", radio_cfg->if_name, ret);

    if (ret == false) {
        LOG(ERR, "%s: failed to trigger scan, aborting", radio_cfg->if_name);
        (*scan_cb)(scan_ctx, ret);
    }
    return true;
}

static int nl80211_scan_abort_recv(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

struct nl80211_scan *nl80211_scan_find(const char *name)
{
    struct nl80211_scan *nl80211_scan = avl_find_element(&nl80211_scan_tree, name, nl80211_scan, avl);

    if (!nl80211_scan)
        LOGN("%s: scan context does not exist", name);

    return nl80211_scan;
}

void nl80211_scan_del(struct nl80211_scan *nl80211_scan)
{
    LOGT("%s: delete scan context", nl80211_scan->name);
    ev_async_stop(EV_DEFAULT, &nl80211_scan->async);
    avl_delete(&nl80211_scan_tree, &nl80211_scan->avl);
    free(nl80211_scan);
}

int nl80211_scan_abort(struct nl_global_info *nl_sm_global, char *ifname)
{
    int if_index;
    struct nl_msg *msg;
    struct nl80211_scan *nl80211_scan;

    nl80211_scan = nl80211_scan_find(ifname);
    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_ABORT_SCAN, false);
    if (!msg) {
        return -EINVAL;
    }
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    if (nl80211_scan)
        nl80211_scan_del(nl80211_scan);

    return nlmsg_send_and_recv(nl_sm_global, msg, nl80211_scan_abort_recv, NULL);
}

bool nl80211_stats_scan_stop(struct nl_global_info *nl_sm_global,
                             radio_entry_t *radio_cfg,
                             radio_scan_type_t scan_type)
{
    char *ifname = radio_cfg->if_name;
    bool ret = true;

    if (nl80211_scan_abort(nl_sm_global, ifname) < 0)
        ret = false;

    LOGT("%s: scan abort returned %d", radio_cfg->if_name, ret);

    return true;
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

int nl80211_scan_dump(struct nl_global_info *nl_sm_global,
                      struct nl_call_param *nl_call_param)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(nl_call_param->ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_GET_SCAN, true);
    if (!msg) {
        return -EINVAL;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    return nlmsg_send_and_recv(nl_sm_global, msg, nl80211_scan_dump_recv, nl_call_param);
}

bool nl80211_stats_scan_get(struct nl_global_info *nl_sm_global,
                            radio_entry_t *radio_cfg, uint32_t *chan_list,
                            uint32_t chan_num, radio_scan_type_t scan_type,
                            dpp_neighbor_report_data_t *scan_results)
{
    struct nl_call_param nl_call_param = {
        .ifname = radio_cfg->if_name,
        .type = radio_cfg->type,
        .list = &scan_results->list,
    };
    bool ret = true;

    if (nl80211_scan_dump(nl_sm_global, &nl_call_param) < 0)
        ret = false;

    LOGT("Parsed %s %s scan results for channel %d",
         radio_get_name_from_type(radio_cfg->type),
         radio_get_scan_name_from_type(scan_type),
         chan_list[0]);
    return ret;
}
