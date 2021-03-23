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
#include <string.h>

#include <ev.h>
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

static target_client_record_t* target_client_record_alloc()
{
    target_client_record_t *record = NULL;

    record = malloc(sizeof(target_client_record_t));
    if (record == NULL)
        return NULL;

    memset(record, 0, sizeof(target_client_record_t));

    return record;
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
        STRSCPY(ssid_entry->ssid, nla_data(tb[NL80211_ATTR_SSID]));
        STRSCPY(ssid_entry->ifname, nla_data(tb[NL80211_ATTR_IFNAME]));
        ds_dlist_insert_tail(nl_call_param->list, ssid_entry);
    }
    return NL_OK;
}

static int nl80211_get_ssid(struct nl_global_info *nl_sm_global,
                                struct nl_call_param *nl_call_param)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(nl_call_param->ifname)) < 0)
        return false;

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_GET_INTERFACE, true);
    if (!msg) {
        return false;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    return nlmsg_send_and_recv(nl_sm_global, msg, nl80211_interface_recv, nl_call_param);
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
    ds_dlist_insert_tail(nl_call_param->list, client_entry);

    return NL_OK;
}

static int nl80211_get_assoclist(struct nl_global_info *nl_sm_global,
                                      struct nl_call_param *nl_call_param)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(nl_call_param->ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_GET_STATION, true);
    if (!msg) {
        return -EINVAL;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nlmsg_send_and_recv(nl_sm_global, msg, nl80211_assoclist_recv, nl_call_param);
    return 0;
}

bool nl80211_stats_clients_get(struct nl_global_info *nl_sm_global,
                               radio_entry_t *radio_cfg,
                               radio_essid_t *essid,
                               target_stats_clients_cb_t *client_cb,
                               ds_dlist_t *client_list, void *client_ctx)
{
//    ds_dlist_t working_list = DS_DLIST_INIT(ds_dlist_t, od_cof);
    ds_dlist_t working_list = DS_DLIST_INIT(target_client_record_t, node);
    ds_dlist_t ssid_list = DS_DLIST_INIT(ssid_list_t, node);
    target_client_record_t *cl;
    ssid_list_t *ssid = NULL;
    struct nl_call_param nl_call_param = {
        .ifname = radio_cfg->if_name,
        .type = radio_cfg->type,
        .list = &working_list,
    //  .list = client_list,
    };
    struct nl_call_param ssid_call_param = {
        .ifname = radio_cfg->if_name,
        .type = radio_cfg->type,
        .list = &ssid_list,
    };
    bool ret = true;

    if (nl80211_get_ssid(nl_sm_global, &ssid_call_param) < 0)
        ret = false;

    while (!ds_dlist_is_empty(&ssid_list)) {
        ssid = ds_dlist_head(&ssid_list);

        nl_call_param.ifname  = ssid->ifname;
        //nl_call_param.list = &working_list;

        if (nl80211_get_assoclist(nl_sm_global, &nl_call_param) < 0) {
            ds_dlist_remove(&ssid_list,ssid);
            continue;
        }
        LOGD("%s: assoc returned %d, list %d", ssid->ifname, ret, ds_dlist_is_empty(&working_list));

        while (!ds_dlist_is_empty(&working_list)) {
            cl = ds_dlist_head(&working_list);
            STRSCPY(cl->info.essid, ssid->ssid);
            ds_dlist_remove(&working_list, cl);
            ds_dlist_insert_tail(client_list, cl);
        }
        ds_dlist_remove(&ssid_list,ssid);
        free(ssid);
    }

    (*client_cb)(client_list, client_ctx, ret);
    return ret;
}

bool nl80211_client_stats_convert(radio_entry_t *radio_cfg, target_client_record_t *data_new,
                                  target_client_record_t *data_old, dpp_client_record_t *client_record)
{
    memcpy(client_record->info.mac, data_new->info.mac, sizeof(data_new->info.mac));
    memcpy(client_record->info.essid, data_new->info.essid, sizeof(radio_cfg->if_name));

    client_record->stats.rssi       = data_new->stats.rssi;
    client_record->stats.rate_tx    = data_new->stats.rate_tx;
    client_record->stats.rate_rx    = data_new->stats.rate_rx;
    client_record->stats.bytes_tx   = data_new->stats.bytes_tx   - data_old->stats.bytes_tx;
    client_record->stats.bytes_rx   = data_new->stats.bytes_rx   - data_old->stats.bytes_rx;
    client_record->stats.frames_tx  = data_new->stats.frames_tx  - data_old->stats.frames_tx;
    client_record->stats.frames_rx  = data_new->stats.frames_rx  - data_old->stats.frames_rx;
    client_record->stats.retries_tx = data_new->stats.retries_tx - data_old->stats.retries_tx;
    client_record->stats.errors_tx  = data_new->stats.errors_tx  - data_old->stats.errors_tx;
    client_record->stats.errors_rx  = data_new->stats.errors_rx  - data_old->stats.errors_rx;

    LOGT("Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
         "bytes_tx=%llu",
         radio_get_name_from_type(radio_cfg->type),
         MAC_ADDRESS_PRINT(data_new->info.mac),
         client_record->stats.bytes_tx);

    return true;
}
