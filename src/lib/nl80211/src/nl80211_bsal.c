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
#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

#include "os_nif.h"

#include "bsal.h"

int nl_resp_parse_ssid(struct nl_msg *msg, void *arg)
{
    char *ssid = arg;
    int len = 0;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_SSID]) {
        LOGT("SSID information unavailable");
        return NL_SKIP;
    }

    len = nla_len(tb[NL80211_ATTR_SSID]);
    strlcpy(ssid, nla_data(tb[NL80211_ATTR_SSID]), (len > SSID_MAX_LEN) ? SSID_MAX_LEN : (len + 1));

    return NL_OK;
}

int nl_req_get_ssid(struct nl_global_info *bsal_nl_global, const char *ifname, char *ssid)
{
    int if_index = -EINVAL;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return false;

    msg = nlmsg_init(bsal_nl_global, NL80211_CMD_GET_INTERFACE, false);
    if (!msg)
        return false;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    return nlmsg_send_and_recv(bsal_nl_global, msg, nl_resp_parse_ssid, ssid);
}

int nl_resp_parse_noise(struct nl_msg *msg, void *arg)
{
    struct noise_info *noise_info = (struct noise_info *) arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *infoattr[NL80211_SURVEY_INFO_MAX + 1];
    static struct nla_policy s_policy[NL80211_SURVEY_INFO_MAX + 1] = {
        [NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_SURVEY_INFO_NOISE]     = { .type = NLA_U8 },
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_SURVEY_INFO])
        return NL_SKIP;

    if (nla_parse_nested(infoattr, NL80211_SURVEY_INFO_MAX, tb[NL80211_ATTR_SURVEY_INFO], s_policy))
        return NL_SKIP;

    if (!infoattr[NL80211_SURVEY_INFO_FREQUENCY])
        return NL_SKIP;

    if (util_freq_to_chan(nla_get_u32(infoattr[NL80211_SURVEY_INFO_FREQUENCY])) != noise_info->chan)
        return NL_SKIP;

    if (!infoattr[NL80211_SURVEY_INFO_NOISE])
        return NL_SKIP;

    noise_info->noise = (int8_t) nla_get_u8(infoattr[NL80211_SURVEY_INFO_NOISE]);
    LOGD("%s: noise %d dBm", __func__, noise_info->noise);

    return NL_SKIP;
}

int rssi_to_snr(struct nl_global_info *nl_global, int if_idx, int rssi)
{
    struct nl_msg *msg;
    struct noise_info noise_info = { 0 };

    if (if_idx < 0) {
        LOGD("%s: Invalid interface index", __func__);
        return (rssi - DEFAULT_NOISE_FLOOR);
    }

    noise_info.chan = nl_req_get_iface_curr_chan(nl_global, if_idx);
    if (noise_info.chan <= 0 || noise_info.chan >= IEEE80211_CHAN_MAX)
        return (rssi - DEFAULT_NOISE_FLOOR);

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_SURVEY, true);
    if (!msg)
        return (rssi - DEFAULT_NOISE_FLOOR);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_idx);

    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_noise, &noise_info);
    if (noise_info.noise)
        return (rssi - noise_info.noise);

    return (rssi - DEFAULT_NOISE_FLOOR);
}

int nl_resp_parse_sta_rssi(struct nl_msg *msg, void *arg)
{
    struct nlattr       *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr   *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr       *sinfo[NL80211_STA_INFO_MAX + 1] = { 0 };
    int8_t              *rssi = (int8_t *)arg;

    static struct nla_policy    sta_info_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_SIGNAL_AVG]    = { .type = NLA_U8     },
    };

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_STA_INFO])
        return NL_SKIP;

    if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], sta_info_policy))
        return NL_SKIP;

    if (sinfo[NL80211_STA_INFO_SIGNAL_AVG])
        *rssi = (int8_t) nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);

    return NL_OK;
}

int nl_req_get_sta_rssi(struct nl_global_info *bsal_nl_global,
                        const char *ifname,
                        const uint8_t *mac_addr,
                        int8_t *rssi)
{
    struct nl_msg *msg;
    int if_index = -EINVAL;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(bsal_nl_global, NL80211_CMD_GET_STATION, false);
    if (!msg)
        return -EINVAL;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    nla_put(msg, NL80211_ATTR_MAC, MAC_ADDR_LEN, mac_addr);

    nlmsg_send_and_recv(bsal_nl_global, msg, nl_resp_parse_sta_rssi, rssi);

    return 0;
}

int nl_resp_parse_sta_info(struct nl_msg *msg, void *arg)
{
    size_t ies_len;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    bsal_cli_info *data = (bsal_cli_info *) arg;
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1] = { };
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
        [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_RX_BYTES64] = { .type = NLA_U64 },
        [NL80211_STA_INFO_TX_BYTES64] = { .type = NLA_U64 },
        [NL80211_STA_INFO_SIGNAL_AVG] = { .type = NLA_U8 },
    };

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_STA_INFO])
        return NL_SKIP;

    if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], stats_policy))
        return NL_SKIP;

    data->rssi = 0;

    if (sinfo[NL80211_STA_INFO_RX_BYTES64])
        data->rx_bytes =
                (uint64_t) nla_get_u64(sinfo[NL80211_STA_INFO_RX_BYTES64]);
    else if (sinfo[NL80211_STA_INFO_RX_BYTES])
        data->rx_bytes =
                (uint64_t) nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);

    if (sinfo[NL80211_STA_INFO_TX_BYTES64])
        data->tx_bytes =
                (uint64_t) nla_get_u64(sinfo[NL80211_STA_INFO_TX_BYTES64]);
    else if (sinfo[NL80211_STA_INFO_TX_BYTES])
        data->tx_bytes =
                (uint64_t) nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);

    if (sinfo[NL80211_STA_INFO_SIGNAL_AVG]) {
        data->rssi =
            (int8_t) nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);
    }

    data->connected = true;

    if (!tb[NL80211_ATTR_IE])
        return NL_OK;

    ies_len = nla_len(tb[NL80211_ATTR_IE]);
    if ((ies_len > 0) && (ies_len < sizeof(data->assoc_ies))) {
        memcpy(data->assoc_ies, nla_data(tb[NL80211_ATTR_IE]), ies_len);
        data->assoc_ies_len = ies_len;
    } else if (ies_len > sizeof(data->assoc_ies)) {
        LOGI("%s: received assoc ie length[%d] exceeds bsal assoc_ies buffer len[%d]",
             __func__, ies_len, sizeof(data->assoc_ies));
    }
    return NL_OK;
}

int nl_req_get_sta_info(struct nl_global_info *bsal_nl_global, const char *ifname, const uint8_t *mac_addr, bsal_cli_info *data)
{
    struct nl_msg *msg;
    int if_index;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(bsal_nl_global, NL80211_CMD_GET_STATION, false);
    if (!msg)
        return -EINVAL;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nla_put(msg, NL80211_ATTR_MAC, MAC_ADDR_LEN, mac_addr);

    nlmsg_send_and_recv(bsal_nl_global, msg, nl_resp_parse_sta_info, data);
    if (data->rssi)
        data->snr = rssi_to_snr(bsal_nl_global, if_index, data->rssi);
    return 0;
}

int bsal_nl_event_parse(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr   *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr       *tb[NL80211_ATTR_MAX + 1];

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    switch (gnlh->cmd) {
        case NL80211_CMD_CONN_FAILED:
            bsal_nl_evt_parse_conn_failed(tb);
            break;
        default:
            break;
    }

    return NL_OK;
}
