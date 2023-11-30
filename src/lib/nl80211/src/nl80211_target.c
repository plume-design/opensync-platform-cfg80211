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

#include <string.h>

#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <net/if.h>

#include "wiphy_info.h"

#define MBM_TO_DBM(gain) ((gain) / 100)
#define DBM_TO_MBM(gain) ((gain) * 100)

int nl_resp_parse_ht_mode(struct nl_msg *msg, void *arg)
{
    int *ht_mode = (int *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_CHANNEL_WIDTH])
    {
        LOGT("HT type is not available\n");
        return NL_SKIP;
    }
    *ht_mode = nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]);
    return NL_SKIP;
}

bool nl_req_get_ht_mode(struct nl_global_info *nl_global,
                        const char *ifname,
                        char *ht_mode,
                        int len)
{
    int if_index = -EINVAL;
    int ht_type = -EINVAL;
    struct nl_msg *msg;
    enum nl80211_chan_width chanwidth;

    if (!nl_global)
        return false;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return false;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_INTERFACE, false);
    if (!msg)
        return false;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_ht_mode, &ht_type);
    chanwidth = ht_type;

    return util_ht_mode(chanwidth, ht_mode, len);
}

int nl_resp_parse_iface_phy_idx(struct nl_msg *msg, void *arg)
{
    int *phy = arg;
    struct nlattr *attr;

    attr = nlmsg_find_attr(nlmsg_hdr(msg),
                           NLMSG_ALIGN(sizeof(struct genlmsghdr)),
                           NL80211_ATTR_WIPHY);
    if (attr)
        *phy = nla_get_u32(attr);

    return NL_SKIP;
}

/* Fetch phy index from interface */
int nl_req_get_iface_phy_idx(struct nl_global_info *nl_global, int if_index)
{
    struct nl_msg *msg;
    int phy_idx = -EINVAL;

    if (!nl_global)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_INTERFACE, false);
    if (!msg)
        return -ENOMEM;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_iface_phy_idx, &phy_idx);

    return phy_idx;
}

static int nl_resp_parse_txpwr(struct nl_msg *msg, void *txpwr)
{
    int *txp = (int *)txpwr;
    struct genlmsghdr   *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr       *tb[NL80211_ATTR_MAX + 1];

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL])
        return -EINVAL;

    *txp = MBM_TO_DBM(nla_get_u32(tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]));
    LOGT("%s: txpower %d", __func__, *txp);

    return NL_OK;
}

int nl_req_get_txpwr(struct nl_global_info *nl_global, const char *ifname)
{
    int if_idx = -EINVAL;
    int txpwr = 0;
    struct nl_msg *msg;

    if (!nl_global)
        return -EINVAL;

    if ((if_idx = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_INTERFACE, false);
    if (!msg)
        return -EINVAL;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_idx);
    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_txpwr, &txpwr);

    return txpwr;
}

int nl_req_set_txpwr(struct nl_global_info *nl_global, const char *ifname, const int dbm)
{
    int phy_idx = -EINVAL;
    struct nl_msg *msg;
    enum nl80211_tx_power_setting type;

    if (!nl_global)
        return -EINVAL;

    if ((phy_idx = util_sys_phyname_to_idx(ifname)) < 0)
        return -EINVAL;

    type = NL80211_TX_POWER_LIMITED;

    msg = nlmsg_init(nl_global, NL80211_CMD_SET_WIPHY, false);
    if (!msg)
        return -EINVAL;

    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);

    nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_SETTING, type);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_LEVEL, DBM_TO_MBM(dbm));
    nlmsg_send_and_recv(nl_global, msg, NULL, NULL);

    return 0;
}

int nl_resp_parse_antanna(struct nl_msg *msg, void *arg)
{
    int *antenna_info = arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_WIPHY]) {
        if (tb[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX])
            antenna_info[0] = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX]);

        if (tb[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX])
            antenna_info[1] = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX]);

        if (tb[NL80211_ATTR_WIPHY_ANTENNA_TX])
            antenna_info[2] = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_TX]);

        if (tb[NL80211_ATTR_WIPHY_ANTENNA_RX])
            antenna_info[3] = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_RX]);
    }

    return NL_SKIP;
}

int nl_req_get_antenna(struct nl_global_info *nl_global, const char *ifname,
                       int *avail_tx_antenna, int *avail_rx_antenna,
                       int *tx_antenna, int *rx_antenna)
{
    struct nl_msg *msg;
    int antenna_info[4] = { 0 }; /* 0-1: available Tx/Rx, 2-3: current Tx/Rx */
    int phy_idx = -EINVAL;

    if (!nl_global)
        return -EINVAL;

    if ((phy_idx = util_sys_phyname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_WIPHY, false);
    if (!msg)
        return -ENOMEM;

    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);

    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);

    nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;

    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_antanna, antenna_info);

    if (antenna_info[0] == 0 || antenna_info[1] == 0 ||
        antenna_info[2] == 0 || antenna_info[3] == 0)
        return -EINVAL;

    if (avail_tx_antenna)   *avail_tx_antenna = antenna_info[0];
    if (avail_rx_antenna)   *avail_rx_antenna = antenna_info[1];
    if (tx_antenna)         *tx_antenna = antenna_info[2];
    if (rx_antenna)         *rx_antenna = antenna_info[3];

    return 0;
}

int nl_req_set_antenna(struct nl_global_info *nl_global, const char *ifname,
                       const int tx_antenna, const int rx_antenna)
{
    int phy_idx = -EINVAL;
    struct nl_msg *msg;

    if (!nl_global)
        return -EINVAL;

    if ((phy_idx = util_sys_phyname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_SET_WIPHY, false);
    if (!msg)
        return -EINVAL;

    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);

    nla_put_u32(msg, NL80211_ATTR_WIPHY_ANTENNA_TX, tx_antenna);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_ANTENNA_RX, rx_antenna);
    nlmsg_send_and_recv(nl_global, msg, NULL, NULL);

    return 0;
}

char *dfs_state_string(enum nl80211_dfs_state state)
{
    switch (state) {
    case NL80211_DFS_USABLE:
        return "DFS_NOP_FINISHED";
    case NL80211_DFS_AVAILABLE:
        return "DFS_CAC_COMPLETED";
    case NL80211_DFS_UNAVAILABLE:
        return "DFS_NOP_STARTED";
    default:
        return "UNKNOWN";
    }
}

int nl_resp_parse_channels(struct nl_msg *msg, void *arg)
{
    int     rband;
    int     rfreq;
    int     state;
    int     channel = 0;
    char    temp_buf[BFR_SIZE_64] = "";
    struct nlattr *nl_band;
    struct nlattr *nl_freq;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct data_buffer_4k *buf = (struct data_buffer_4k *) arg;
    static struct nla_policy f_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
        [NL80211_FREQUENCY_ATTR_FREQ]       = { .type = NLA_U32 },
        [NL80211_FREQUENCY_ATTR_DISABLED]   = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_RADAR]      = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_DFS_STATE]  = { .type = NLA_U32 },
    };

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_WIPHY_BANDS])
        return NL_SKIP;

    nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rband) {
        nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

        if (!tb_band[NL80211_BAND_ATTR_FREQS])
            return NL_SKIP;

        nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rfreq) {
            nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq), nla_len(nl_freq), f_policy);

            if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
                continue;

            channel = util_freq_to_chan(nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]));
            if (!channel || tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
                continue;

            if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE])
                state = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]);
            else
                state = -EINVAL;

            if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR])
                snprintf(temp_buf, sizeof(temp_buf), "chan %d DFS %s\n", channel, dfs_state_string(state));
            else
                snprintf(temp_buf, sizeof(temp_buf), "chan %d\n", channel);

            if ((strlen(buf->buf) + strlen(temp_buf)) < buf->len)
                strcat(buf->buf, temp_buf);
            else
                return NL_SKIP;
        }
    }

    return NL_SKIP;
}

int nl_req_get_channels(struct nl_global_info *nl_global,
                        const char *ifname,
                        char *buf,
                        int len)
{
    struct nl_msg *msg;
    int phy_idx = -EINVAL;
    struct data_buffer_4k chan_buf = { "", BFR_SIZE_4K};

    if (!nl_global)
        return -EINVAL;

    if ((phy_idx = util_sys_phyname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_WIPHY, true);
    if (!msg) return -ENOMEM;

    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);
    nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;

    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_channels, &chan_buf);

    strlcpy(buf, chan_buf.buf, len);

    return 0;
}

int nl_resp_parse_init_channels(struct nl_msg *msg, void *arg)
{
    int     rband;
    int     rfreq;
    int     channel = 0;
    struct nlattr *nl_band;
    struct nlattr *nl_freq;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct channel_status *chan_stat = (struct channel_status *)arg;
    enum nl80211_dfs_state dfs_state = -EINVAL;
    static struct nla_policy f_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
        [NL80211_FREQUENCY_ATTR_FREQ]       = { .type = NLA_U32 },
        [NL80211_FREQUENCY_ATTR_DISABLED]   = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_RADAR]      = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_DFS_STATE]  = { .type = NLA_U32 },
    };

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_WIPHY_BANDS])
        return NL_SKIP;

    nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rband) {
        nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

        if (!tb_band[NL80211_BAND_ATTR_FREQS])
            return NL_SKIP;

        nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rfreq) {
            nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq), nla_len(nl_freq), f_policy);

            if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
                continue;

            channel = util_freq_to_chan(nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]));
            if (!channel || tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
                continue;

            if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR])
                chan_stat[channel].state = NOP_FINISHED;
            else
                chan_stat[channel].state = ALLOWED;

            if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE])
                dfs_state = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]);

            if (dfs_state == NL80211_DFS_AVAILABLE)
                chan_stat[channel].state = CAC_COMPLETED;
            else if (dfs_state == NL80211_DFS_UNAVAILABLE)
                chan_stat[channel].state = NOP_STARTED;
        }
    }

    return NL_SKIP;
}

int nl_req_init_channels(struct nl_global_info *nl_global,
                         const char *ifname,
                         struct channel_status *chan_status)
{
    struct nl_msg *msg;
    int phy_idx = -EINVAL;
    int iface_index = -EINVAL;

    if (!nl_global)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_WIPHY, true);
    if (!msg) return -ENOMEM;

    if (ifname) {
        if ((iface_index = util_sys_ifname_to_idx(ifname)) < 0)
            return -EINVAL;

        if ((phy_idx = nl_req_get_iface_phy_idx(nl_global, iface_index)) < 0)
            return -EINVAL;

        nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);
    }

    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);

    nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;

    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_init_channels, chan_status);

    return 0;
}

int nl_req_del_iface(struct nl_global_info *nl_global, const char *ifname)
{
    struct nl_msg *msg;
    int err = 0;
    int phy_idx = -EINVAL;
    int iface_index = -EINVAL;

    if (!nl_global)
        return -EINVAL;

    if ((iface_index = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    if ((phy_idx = nl_req_get_iface_phy_idx(nl_global, iface_index)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_DEL_INTERFACE, false);
    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);

    err = nlmsg_send_and_recv(nl_global, msg, NULL, NULL);

    return err;
}

int nl_req_add_iface(struct nl_global_info *nl_global,
                     const char *new_vif_name,
                     const char *r_ifname,
                     const char *mode, char *mac_addr)
{
    struct nl_msg *msg;
    int err = 0;
    int phy_idx = -EINVAL;
    enum nl80211_iftype iftype;

    if (!nl_global)
        return -EINVAL;

    if (mode_to_nl80211_attr_iftype(mode, &iftype) < 0)
        return -EINVAL;

    if ((phy_idx = util_sys_phyname_to_idx(r_ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_NEW_INTERFACE, false);
    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);
    nla_put_u32(msg, NL80211_ATTR_IFTYPE, iftype);
    nla_put_string(msg, NL80211_ATTR_IFNAME, new_vif_name);
    nla_put(msg, NL80211_ATTR_MAC, MAC_ADDR_LEN, mac_addr);
    nla_put_flag(msg, NL80211_ATTR_IFACE_SOCKET_OWNER);

    err = nlmsg_send_and_recv(nl_global, msg, NULL, NULL);

    return err;
}

int nl_resp_parse_iface_curr_chan(struct nl_msg *msg, void *arg)
{
    int *channel = arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_WIPHY_FREQ])
        *channel = util_freq_to_chan(nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]));

    return NL_SKIP;
}

int nl_req_get_iface_curr_chan(struct nl_global_info *nl_global, int if_index)
{
    int curr_chan = 0;
    struct nl_msg *msg;

    if (!nl_global)
        return -EINVAL;

    if (if_index < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_INTERFACE, false);
    if (!msg)
        return -ENOMEM;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_iface_curr_chan, &curr_chan);

    return curr_chan;
}

int nl_resp_parse_iface_supp_band(struct nl_msg *msg, void *arg)
{
    int *flags = arg;
    int channel;
    int chan_flag = 0;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_WIPHY_BANDS]) {
        struct nlattr *nl_band = NULL;
        int rem_band = 0;

        nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
            struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];

            if (nl_band->nla_type == NL80211_BAND_2GHZ) {
                *flags = CHAN_2GHZ;
            } else if (nl_band->nla_type == NL80211_BAND_6GHZ) {
                *flags = CHAN_6GHZ;
            } else {
                nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);
                if (tb_band[NL80211_BAND_ATTR_FREQS]) {
                    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
                    struct nlattr *nl_freq = NULL;
                    int rem_freq = 0;

                    nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
                        static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
                            [NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
                            [NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
                        };

                        nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq), nla_len(nl_freq), freq_policy);
                        if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
                            continue;
                        if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
                            continue;

                        channel = util_freq_to_chan(nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]));
                        chan_classify(channel, &chan_flag);
                        if (*flags == -EINVAL) {
                            // first time the call back function is called
                            *flags = chan_flag;
                        } else {
                            // combine with the last channel parsing result
                            *flags |= chan_flag;
                        }
                    }
                }
            }
        }
    }

    return NL_SKIP;
}

int nl_req_get_iface_supp_band(struct nl_global_info *nl_global, const char *ifname)
{
    struct nl_msg *msg;
    int flags = -EINVAL;
    int phy_idx = -EINVAL;

    if (!nl_global)
        return -EINVAL;

    if ((phy_idx = util_sys_phyname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_WIPHY, false);
    if (!msg)
        return -ENOMEM;

    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);

    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);

    nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;

    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_iface_supp_band, &flags);

    return flags;
}

int nl_resp_parse_iface_ht_capa(struct nl_msg *msg, void *arg)
{
    int *ht_capa = arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_WIPHY_BANDS]) {
        struct nlattr *nl_band = NULL;
        int rem_band = 0;

        nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
            struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
            nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);
            if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
                *ht_capa = nla_get_u32(tb_band[NL80211_BAND_ATTR_HT_CAPA]);
            }
        }
    }

    return NL_SKIP;
}

int nl_req_get_iface_ht_capa(struct nl_global_info *nl_global, const char *ifname)
{
    struct nl_msg *msg;
    int htCapa = -EINVAL;
    int phy_idx = -EINVAL;

    if (!nl_global)
        return -EINVAL;

    if ((phy_idx = util_sys_phyname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_WIPHY, false);
    if (!msg)
        return -ENOMEM;

    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);

    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);

    nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;

    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_iface_ht_capa, &htCapa);

    return htCapa;
}

int nl_resp_parse_iface_vht_capa(struct nl_msg *msg, void *arg)
{
    int *vht_capa = arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_WIPHY_BANDS]) {
        struct nlattr *nl_band = NULL;
        int rem_band = 0;

        nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
            struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
            nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);
            if (tb_band[NL80211_BAND_ATTR_VHT_CAPA]) {
                *vht_capa = nla_get_u32(tb_band[NL80211_BAND_ATTR_VHT_CAPA]);
            }
        }
    }

    return NL_SKIP;
}

int nl_req_get_iface_vht_capa(struct nl_global_info *nl_global, const char *ifname)
{
    struct nl_msg *msg;
    int vhtCapa = -EINVAL;
    int phy_idx = -EINVAL;

    if (!nl_global)
        return -EINVAL;

    if ((phy_idx = util_sys_phyname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_WIPHY, false);
    if (!msg)
        return -ENOMEM;

    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);

    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);

    nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;

    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_iface_vht_capa, &vhtCapa);

    return vhtCapa;
}

int nl_req_set_reg_dom(struct nl_global_info *nl_global, char *country_code)
{
    struct nl_msg *msg;

    if (!nl_global)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_REQ_SET_REG, false);
    if (nla_put_string(msg, NL80211_ATTR_REG_ALPHA2, country_code)) {
        nlmsg_free(msg);
        LOGT("Failed to set country code");
        return -1;
    }

    if (nlmsg_send_and_recv(nl_global, msg, NULL, NULL))
        return -1;

    return 0;
}

int nl_resp_parse_reg_dom(struct nl_msg *msg, void *arg)
{
    char *country_code = arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    memset(tb, 0, sizeof(tb));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_REG_ALPHA2]) {
        LOGT("Country information unavailable");
        return NL_SKIP;
    }

    strlcpy(country_code, nla_data(tb[NL80211_ATTR_REG_ALPHA2]), 3);

    LOGT("Country code[%s]", country_code);

    return NL_SKIP;
}

int nl_req_get_reg_dom(struct nl_global_info *nl_global, char *buf)
{
    struct nl_msg *msg;

    if (!nl_global)
        return -EINVAL;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_REG, true);
    if (!msg) return -ENOMEM;

    return nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_reg_dom, buf);
}

int nl_resp_parse_mode(struct nl_msg *msg, void *arg)
{
    int *type = (int *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_IFTYPE]) {
        LOGT("Mode unspecified\n");
        return NL_SKIP;
    }
    *type = nla_get_u32(tb[NL80211_ATTR_IFTYPE]);
    return NL_SKIP;
}

bool nl_req_get_mode(struct nl_global_info *nl_global,
                     const char *ifname,
                     char *mode,
                     int len)
{
    int if_index = -EINVAL;
    int mode_type = -EINVAL;
    struct nl_msg *msg;
    enum nl80211_iftype type = NL80211_IFTYPE_UNSPECIFIED;

    if (!nl_global)
        return -EINVAL;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return false;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_INTERFACE, false);
    if (!msg)
        return false;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_mode, &mode_type);
    type = mode_type;

    return util_mode(type, mode, len);
}

#if 0
#include <ev.h>

static ev_io            nl_ev_loop;

static int nl_event_parse(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    char ifname[IFNAMSIZ] = {'\0'};
    char phyname[IFNAMSIZ] = {'\0'};
    int ifidx = -1;
    int phy = -1;

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFINDEX]) {
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
        if_indextoname(ifidx, ifname);
    } else if (tb[NL80211_ATTR_IFNAME]) {
        STRSCPY(ifname, nla_get_string(tb[NL80211_ATTR_IFNAME]));
    }

    if (tb[NL80211_ATTR_WIPHY]) {
        phy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
        if (tb[NL80211_ATTR_WIPHY_NAME])
            STRSCPY(phyname, nla_get_string(tb[NL80211_ATTR_WIPHY_NAME]));
        else
            snprintf(phyname, sizeof(phyname), "phy%d", phy);
    }

    switch (gnlh->cmd) {
        case NL80211_CMD_NEW_INTERFACE:
        case NL80211_CMD_NEW_WIPHY:
        case NL80211_CMD_GET_WIPHY:
        case NL80211_CMD_NEW_STATION:
        case NL80211_CMD_DEL_STATION:
        case NL80211_CMD_DEL_INTERFACE:
        case NL80211_CMD_DEL_WIPHY:
        default:
            LOGT("%s: ifname=%s phyname=%s command=%d",
                __func__, ifname, phyname, gnlh->cmd);
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

static void nl_ev_handler(struct ev_loop *ev, struct ev_io *io, int event)
{
    int res = -EINVAL;

    nl_cb_err(nl_global.nl_cb, NL_CB_CUSTOM, err_handler, NULL);
    nl_cb_set(nl_global.nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);
    nl_cb_set(nl_global.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(nl_global.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl_event_parse, NULL);

    res = nl_recvmsgs(nl_global.nl_evt_handle, nl_global.nl_cb);
    if (res < 0)
        LOGT("Failed to receive event message");
}

void netlink_mcast_event_register(struct nl_global_info *nl_global)
{
    add_mcast_subscription(nl_global, "config");
    add_mcast_subscription(nl_global, "mlme");
    add_mcast_subscription(nl_global, "vendor");

    ev_io_init(&nl_ev_loop, nl_ev_handler, nl_socket_get_fd(nl_global.nl_evt_handle), EV_READ);
    ev_io_start(loop, &nl_ev_loop);
}
#endif

int netlink_wm_init(struct nl_global_info *nl_global)
{
    if (!nl_global)
        return -EINVAL;

    if (netlink_init(nl_global) < 0) {
        LOGT("nl80211: failed to connect\n");
        return -1;
    }

    /* Can be used to register for netlink events */
    //netlink_mcast_event_register(nl_global);

    return 0;
}
