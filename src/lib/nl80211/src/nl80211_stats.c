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
#include "nl80211_stats.h"

struct nl_global_info nl_sm_global;
static ev_io nl_sm_loop;

bool nl_stats_clients_get(radio_entry_t *radio_cfg, radio_essid_t *essid,
                               target_stats_clients_cb_t *client_cb,
                               ds_dlist_t *client_list, void *client_ctx)
{
    return nl80211_stats_clients_get(&nl_sm_global,
                                     radio_cfg,
                                     essid,
                                     client_cb,
                                     client_list,
                                     client_ctx);
}

bool nl_stats_survey_get(radio_entry_t *radio_cfg, uint32_t *chan_list,
                         uint32_t chan_num, radio_scan_type_t scan_type,
                         target_stats_survey_cb_t *survey_cb,
                         ds_dlist_t *survey_list, void *survey_ctx)
{
    return nl80211_stats_survey_get(&nl_sm_global,
                                    radio_cfg,
                                    chan_list,
                                    chan_num,
                                    scan_type,
                                    survey_cb,
                                    survey_list,
                                    survey_ctx);
}

bool nl_stats_scan_start(radio_entry_t *radio_cfg, uint32_t *chan_list,
                            uint32_t chan_num, radio_scan_type_t scan_type,
                            int32_t dwell_time, target_scan_cb_t *scan_cb,
                            void *scan_ctx)
{
    return nl80211_stats_scan_start(&nl_sm_global,
                                    radio_cfg,
                                    chan_list,
                                    chan_num,
                                    scan_type,
                                    dwell_time,
                                    scan_cb,
                                    scan_ctx);
}

bool nl_stats_scan_stop(radio_entry_t *radio_cfg, radio_scan_type_t scan_type)
{
    return nl80211_stats_scan_stop(&nl_sm_global, radio_cfg, scan_type);
}

bool nl_stats_scan_get(radio_entry_t *radio_cfg, uint32_t *chan_list,
                       uint32_t chan_num, radio_scan_type_t scan_type,
                       dpp_neighbor_report_data_t *scan_results)
{
    return nl80211_stats_scan_get(&nl_sm_global,
                                  radio_cfg,
                                  chan_list,
                                  chan_num,
                                  scan_type,
                                  scan_results);
}

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

int nl_sm_init(struct ev_loop *sm_evloop)
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
