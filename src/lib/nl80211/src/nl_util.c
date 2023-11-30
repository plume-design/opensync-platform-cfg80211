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

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif

int nl_resp_parse_mcast_id(struct nl_msg *msg, void *arg)
{
    int rem;
    struct nlattr *mcgrp;
    struct mcast_group_id *grp_id = arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[CTRL_ATTR_MCAST_GROUPS])
        return NL_SKIP;

    nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem) {
        struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];

        nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp), nla_len(mcgrp), NULL);

        if (!tb[CTRL_ATTR_MCAST_GRP_NAME] || !tb[CTRL_ATTR_MCAST_GRP_ID])
            continue;

        if (!strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]), grp_id->name, nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME]))) {
            grp_id->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
            break;
        }
    };

    return NL_SKIP;
}

/* Add multicast subscription */
int add_mcast_subscription(struct nl_global_info *nl_global, char *name)
{
    struct nl_msg *msg = NULL;
    struct mcast_group_id grp_id = { name, -EINVAL };
    int ret = -EINVAL;

    if (!nl_global)
        return ret;

    msg = nlmsg_alloc();
    if (!msg)
        return ret;

    if (genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl_global->nl_msg_handle, "nlctrl"),
                    0, 0, CTRL_CMD_GETFAMILY, 0) == NULL)
        goto nla_put_failure;

    if (nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, "nl80211") < 0)
        goto nla_put_failure;

    if (nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_mcast_id, &grp_id) < 0)
        goto nla_put_failure;

    if (grp_id.id >= 0)
        ret = nl_socket_add_membership(nl_global->nl_evt_handle, grp_id.id);

    return ret;

nla_put_failure:
    nlmsg_free(msg);
    return ret;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
    int *err = arg;
    *err = 0;
    return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
    int *err = arg;
    *err = 0;
    return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    int *ret = arg;
    *ret = err->error;
    return NL_SKIP;
}

void set_options(struct nl_sock *handle)
{
    int opt;

    opt = 1;
    setsockopt(nl_socket_get_fd(handle), SOL_NETLINK, NETLINK_EXT_ACK, &opt, sizeof(opt));

    opt = 1;
    setsockopt(nl_socket_get_fd(handle), SOL_NETLINK, NETLINK_CAP_ACK, &opt, sizeof(opt));
}

/* Send out netlink request and parse response in callback handler */
int nlmsg_send_and_recv(struct nl_global_info *nl_global,
                        struct nl_msg *msg,
                        int (*handler) (struct nl_msg *, void *),
                        void *arg)
{
    struct nl_cb *cb = NULL;
    int err = -1;

    if (!msg)
        return -ENOMEM;

    if (!nl_global)
        goto out;

    if (nl_global->nl_cb == NULL)
        goto out;

    cb = nl_cb_clone(nl_global->nl_cb);
    if (!cb)
        goto out;

    if (nl_global->nl_msg_handle == NULL)
        goto out;

    set_options(nl_global->nl_msg_handle);

    /* Finalize Netlink message */
    err = nl_send_auto_complete(nl_global->nl_msg_handle, msg);
    if (err < 0)
        goto out;

    err = 1;
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
    if (handler)
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, handler, arg);

    while (err > 0)
        nl_recvmsgs(nl_global->nl_msg_handle, cb);

out:
    nlmsg_free(msg);
    nl_cb_put(cb);
    return err;
}

/* Initialize netlink message with netlink headers */
struct nl_msg *nlmsg_init(struct nl_global_info *nl_global, int cmd, int dump)
{
    struct nl_msg *msg = NULL;
    int flags = 0;

    if (!nl_global)
        goto out;

    msg = nlmsg_alloc();
    if (!msg)
        goto out;

    if (dump)
        flags |= NLM_F_DUMP;

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nl_global->nl_id, 0, flags, cmd, 0);

out:
    return msg;
}

int netlink_init(struct nl_global_info *nl_global)
{
    if (!nl_global)
        return -1;

    nl_global->nl_cb = nl_cb_alloc(NL_CB_CUSTOM);
    if (nl_global->nl_cb == NULL)
        return -1;

    /* Socket handler for messages */
    nl_global->nl_msg_handle = nl_socket_alloc_cb(nl_global->nl_cb);
    if (nl_global->nl_msg_handle == NULL) {
        LOGT("Failed to allocate nl msg callback handle");
        goto out;
    }

    if (genl_connect(nl_global->nl_msg_handle)) {
        LOGT("Failed to bind to nl msg callback handle");
        goto out;
    }

    nl_global->nl_id = genl_ctrl_resolve(nl_global->nl_msg_handle, "nl80211");
    if (nl_global->nl_id < 0) {
        goto out;
    }

    /* Socket handler for events */
    nl_global->nl_evt_handle = nl_socket_alloc_cb(nl_global->nl_cb);
    if (nl_global->nl_evt_handle == NULL) {
        LOGT("Failed to allocate event callback handle");
        goto out;
    }

    if (genl_connect(nl_global->nl_evt_handle)) {
        LOGT("Failed to bind to event callback handle");
        goto out;
    }

    return 0;
out:
    nl_socket_free(nl_global->nl_msg_handle);
    nl_socket_free(nl_global->nl_evt_handle);
    nl_cb_put(nl_global->nl_cb);
    nl_global->nl_cb = NULL;
    return -1;
}

void netlink_deinit(struct nl_global_info *nl_global)
{
    if (!nl_global)
        return;

    nl_socket_free(nl_global->nl_msg_handle);
    nl_socket_free(nl_global->nl_evt_handle);
    nl_cb_put(nl_global->nl_cb);
    nl_global->nl_cb = NULL;
}

static int nl_resp_parse_noise(struct nl_msg *msg, void *arg)
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

    return NL_SKIP;
}

int util_get_curr_chan_noise(struct nl_global_info *nl_global, int if_idx, int channel)
{
    struct nl_msg *msg;
    struct noise_info noise_info = { 0 };

    if (if_idx < 0) {
        LOGD("%s: Invalid interface index", __func__);
        return DEFAULT_NOISE_FLOOR;
    }

    noise_info.chan = channel;
    if (noise_info.chan <= 0 || noise_info.chan >= IEEE80211_CHAN_MAX)
        return DEFAULT_NOISE_FLOOR;

    msg = nlmsg_init(nl_global, NL80211_CMD_GET_SURVEY, true);
    if (!msg)
        return DEFAULT_NOISE_FLOOR;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_idx);

    if (nlmsg_send_and_recv(nl_global, msg, nl_resp_parse_noise, &noise_info) < 0)
        return 0;

    if (noise_info.noise == 0) noise_info.noise = DEFAULT_NOISE_FLOOR;

    return noise_info.noise;
}
