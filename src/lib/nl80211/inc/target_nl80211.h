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

#include <ev.h>

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

#define MAC_ADDR_LEN 6

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

int add_mcast_subscription(struct nl_global_info *nl_global, char *name);
int nlmsg_send_and_recv(struct nl_global_info *nl_global,
                        struct nl_msg *msg,
                        int (*handler) (struct nl_msg *, void *),
                        void *arg);
struct nl_msg *nlmsg_init(struct nl_global_info *nl_global, int cmd, int dump);
int netlink_init(struct nl_global_info *nl_global);

int util_sys_ifname_to_idx(const char *ifname);
int util_sys_phyname_to_idx(const char *phyname);
int util_freq_to_chan(int freq);
int util_chan_to_freq(int freq);
int mode_to_nl80211_attr_iftype(const char *mode, enum nl80211_iftype *type);
int util_ht_mode(enum nl80211_chan_width chanwidth, char *ht_mode, int len);

// TODO: Remove
#define LOGT(message, ...) \
    do { fprintf(stdout, "[%s +%d - %s()] " message "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__ ); } while(0) ;

#define DBG() LOGT()
#define DBGS() LOGT("START >>>")
#define DBGE() LOGT("<<<   END")
#define SHOW_CMD(cmd) do {                              \
    switch (cmd) {                                      \
    case NL80211_CMD_NEW_STATION:                       \
        LOGT("[NL80211_CMD_NEW_STATION] [%d]", cmd);    \
        break;                                          \
    case NL80211_CMD_DEL_STATION:                       \
        LOGT("[NL80211_CMD_DEL_STATION] [%d]", cmd);    \
        break;                                          \
    case NL80211_CMD_NEW_INTERFACE:                     \
        LOGT("[NL80211_CMD_NEW_INTERFACE] [%d]", cmd);  \
        break;                                          \
    case NL80211_CMD_DEL_INTERFACE:                     \
        LOGT("[NL80211_CMD_DEL_INTERFACE] [%d]", cmd);  \
        break;                                          \
    case NL80211_CMD_DEL_WIPHY:                         \
        LOGT("[NL80211_CMD_DEL_WIPHY] [%d]", cmd);      \
        break;                                          \
    case NL80211_CMD_NEW_WIPHY:                         \
        LOGT("[NL80211_CMD_NEW_WIPHY] [%d]", cmd);      \
        break;                                          \
    case NL80211_CMD_GET_WIPHY:                         \
        LOGT("[NL80211_CMD_GET_WIPHY] [%d]", cmd);      \
        break;                                          \
    case NL80211_CMD_GET_SCAN:                          \
        LOGT("[NL80211_CMD_GET_SCAN] [%d]", cmd);       \
        break;                                          \
    case NL80211_CMD_GET_STATION:                       \
        LOGT("[NL80211_CMD_GET_STATION] [%d]", cmd);    \
        break;                                          \
    case NL80211_CMD_GET_POWER_SAVE:                    \
        LOGT("[NL80211_CMD_GET_POWER_SAVE] [%d]", cmd); \
        break;                                          \
    case NL80211_CMD_GET_REG:                           \
        LOGT("[NL80211_CMD_GET_REG] [%d]", cmd);        \
        break;                                          \
    default:                                            \
        LOGT("Unknown cmd [%d]", cmd);                  \
        break;                                          \
    }                                                   \
} while(0);

#endif /* NL80211_H_INCLUDED */
