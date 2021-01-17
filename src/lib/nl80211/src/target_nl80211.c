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
#include "target_nl80211.h"

#include <string.h>

#include <ev.h>

#include <libubox/avl.h>
#include <libubox/vlist.h>

#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <net/if.h>

static ev_io            nl_ev_loop;
struct nl_global_info   nl_global;

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

bool nl_req_get_ht_mode(const char *ifname, char *ht_mode, int len)
{
    int if_index = -EINVAL;
    int ht_type = -EINVAL;
    struct nl_msg *msg;
    enum nl80211_chan_width chanwidth;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return false;

    msg = nlmsg_init(&nl_global, NL80211_CMD_GET_INTERFACE, false);
    if (!msg)
        return false;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nlmsg_send_and_recv(&nl_global, msg, nl_resp_parse_ht_mode, &ht_type);
    chanwidth = ht_type;

    return util_ht_mode(chanwidth, ht_mode, len);
}

int nl_resp_parse_iface_phy_idx(struct nl_msg *msg, void *arg)
{
    int *phy = arg;
    struct nlattr *attr;

    attr = nlmsg_find_attr(nlmsg_hdr(msg), NLMSG_ALIGN(sizeof(struct genlmsghdr)), NL80211_ATTR_WIPHY);
    if (attr)
        *phy = nla_get_u32(attr);

    return NL_SKIP;
}

/* Fetch phy index from interface */
int nl_req_get_iface_phy_idx(int if_index)
{
    struct nl_msg *msg;
    int phy_idx = -EINVAL;

    msg = nlmsg_init(&nl_global, NL80211_CMD_GET_INTERFACE, false);
    if (!msg)
        return -ENOMEM;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    nlmsg_send_and_recv(&nl_global, msg, nl_resp_parse_iface_phy_idx, &phy_idx);

    return phy_idx;
}

int nl_req_del_iface(const char *ifname)
{
    struct nl_msg *msg;
    int err = 0;
    int phy_idx = -EINVAL;
    int iface_index = -EINVAL;

    if ((iface_index = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    if ((phy_idx = nl_req_get_iface_phy_idx(iface_index)) < 0)
        return -EINVAL;

    msg = nlmsg_init(&nl_global, NL80211_CMD_DEL_INTERFACE, false);
    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);

    err = nlmsg_send_and_recv(&nl_global, msg, NULL, NULL);

    return err;
}

int nl_req_add_iface(const char *new_vif_name, const char *r_ifname, const char *mode, char *mac_addr)
{
    struct nl_msg *msg;
    int err = 0;
    int phy_idx = -EINVAL;
    enum nl80211_iftype iftype;
    int iface_index = -EINVAL;

    if (mode_to_nl80211_attr_iftype(mode, &iftype) < 0)
        return -EINVAL;

    if ((iface_index = util_sys_ifname_to_idx(r_ifname)) < 0)
        return -EINVAL;

    if ((phy_idx = nl_req_get_iface_phy_idx(iface_index)) < 0)
        return -EINVAL;

    msg = nlmsg_init(&nl_global, NL80211_CMD_NEW_INTERFACE, false);
    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);
    nla_put_u32(msg, NL80211_ATTR_IFTYPE, iftype);
    nla_put_string(msg, NL80211_ATTR_IFNAME, new_vif_name);
    nla_put(msg, NL80211_ATTR_MAC, MAC_ADDR_LEN, mac_addr);
    nla_put_flag(msg, NL80211_ATTR_IFACE_SOCKET_OWNER);

    err = nlmsg_send_and_recv(&nl_global, msg, NULL, NULL);

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

int nl_req_get_iface_curr_chan(const char *ifname)
{
    DBG();

    int curr_chan = 0;
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(&nl_global, NL80211_CMD_GET_INTERFACE, false);
    if (!msg)
        return -ENOMEM;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    nlmsg_send_and_recv(&nl_global, msg, nl_resp_parse_iface_curr_chan, &curr_chan);

    return curr_chan;
}

int nl_resp_parse_iface_supp_chan(struct nl_msg *msg, void *arg)
{
    int *channel = arg;
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

                    *channel = util_freq_to_chan(nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]));
                    break;
                }
            }
        }
    }

    return NL_SKIP;
}

int nl_req_get_iface_supp_chan(const char *ifname)
{
    DBG();

    struct nl_msg *msg;
    int channel = -EINVAL;
    int phy_idx = -EINVAL;
    int iface_index = -EINVAL;

    if ((iface_index = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    if ((phy_idx = nl_req_get_iface_phy_idx(iface_index)) < 0)
        return -EINVAL;

    msg = nlmsg_init(&nl_global, NL80211_CMD_GET_WIPHY, false);
    if (!msg)
        return -ENOMEM;

    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);

    nlmsg_send_and_recv(&nl_global, msg, nl_resp_parse_iface_supp_chan, &channel);

    return channel;
}

/* Naming template for set/get request and parsing of received messages
 * nl_req_set_x
 * nl_req_get_x
 * nl_resp_parse_x
 */
int nl_req_set_reg_dom(char *country_code)
{
    DBG();

    struct nl_msg *msg;

    msg = nlmsg_init(&nl_global, NL80211_CMD_REQ_SET_REG, false);
    if (nla_put_string(msg, NL80211_ATTR_REG_ALPHA2, country_code)) {
        nlmsg_free(msg);
        LOGT("Failed to set country code");
        return -1;
    }

    if (nlmsg_send_and_recv(&nl_global, msg, NULL, NULL))
        return -1;

    return 0;
}

int nl_resp_parse_reg_dom(struct nl_msg *msg, void *arg)
{
    DBG();

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

int nl_req_get_reg_dom(char *buf)
{
    DBG();

    struct nl_msg *msg;

    msg = nlmsg_init(&nl_global, NL80211_CMD_GET_REG, true);
    if (!msg) return -ENOMEM;

    return nlmsg_send_and_recv(&nl_global, msg, nl_resp_parse_reg_dom, buf);
}

static void nl80211_add_iface(struct nlattr **tb, char *ifname, char *phyname, int ifidx)
{
    LOGT("ifindex[%d] ifname[%s]", ifidx, ifname);
}

static void nl80211_add_phy(struct nlattr **tb, char *name)
{
     LOGT("phyname[%s]", name);
}

static int nl_event_parse(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    char ifname[IFNAMSIZ] = {'\0'};
    char phyname[IFNAMSIZ] = {'\0'};
    int ifidx = -1, phy = -1;

    memset(tb, 0, sizeof(tb));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

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
    case NL80211_CMD_NEW_INTERFACE:
        nl80211_add_iface(tb, ifname, phyname, ifidx);
        break;
    case NL80211_CMD_NEW_WIPHY:
    case NL80211_CMD_GET_WIPHY:
        nl80211_add_phy(tb, phyname);
        break;
#if 0
    case NL80211_CMD_NEW_STATION:
        nl80211_add_station(tb, ifname);
        break;
    case NL80211_CMD_DEL_STATION:
        nl80211_del_station(tb, ifname);
        break;
    case NL80211_CMD_DEL_INTERFACE:
        nl80211_del_iface(tb, ifname);
        break;
    case NL80211_CMD_DEL_WIPHY:
        nl80211_del_phy(tb, phyname);
        break;
#endif
    default:
        LOGT("gnlh->cmd [%d]", gnlh->cmd);
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

int netlink_global_init(struct ev_loop *loop)
{
    DBG();

    if (netlink_init(&nl_global) < 0) {
        LOGT("nl80211: failed to connect\n");
        return -1;
    }

    if (!loop)
        return -1;

    add_mcast_subscription(&nl_global, "config");
    add_mcast_subscription(&nl_global, "mlme");
    add_mcast_subscription(&nl_global, "vendor");

    ev_io_init(&nl_ev_loop, nl_ev_handler, nl_socket_get_fd(nl_global.nl_evt_handle), EV_READ);
    ev_io_start(loop, &nl_ev_loop);

    return 0;
}

void netlink_global_deinit(void)
{
    nl_socket_free(nl_global.nl_msg_handle);
    nl_socket_free(nl_global.nl_evt_handle);
    nl_cb_put(nl_global.nl_cb);
    nl_global.nl_cb = NULL;
}

void target_nl80211_init(struct ev_loop *loop)
{
    DBG();

    netlink_global_init(loop);

    //TODO [Remove]
    //nl_req_set_reg_dom("FR");
    //nl_req_get_iface_chan("home_ap_24");

    return;
}