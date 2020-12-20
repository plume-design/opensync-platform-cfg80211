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

#ifndef IOCTL80211_NETLINK_11AX_H_INCLUDED
#define IOCTL80211_NETLINK_11AX_H_INCLUDED
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/ether.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <netlink/attr.h>
#include <linux/netlink.h>
#ifdef EXQCA
//#include <nl80211_copy.h>
//#include <cfg80211_nlwrapper_api.h>
//#include <cfg80211_external.h>
//#include <if_athioctl.h>
//#include <qca_vendor.h>
//#include "ieee80211_external.h"
#endif
#include <signal.h>
#include <linux/version.h>
#include "ioctl80211_client.h"

#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN  1234
#endif
#ifndef _BIG_ENDIAN
#define _BIG_ENDIAN 4321
#endif

#ifndef ATH_SUPPORT_LINUX_STA
#include <asm/byteorder.h>
#endif
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif
#if BUILD_X86
struct cfg80211_data {
    void *data;
    unsigned int length;
    unsigned int flags;
    unsigned int parse_data;
    void (*callback) (struct cfg80211_data *);
};
#endif

#ifdef EXQCA
struct ioctl80211_vap_stats
{
    struct ieee80211_stats          vap_stats;
    struct ieee80211_mac_stats      vap_unicast_stats;
    struct ieee80211_mac_stats      vap_multicast_stats;
};
#endif

#define DEFAULT_NL80211_CMD_SOCK_ID 777
#define DEFAULT_NL80211_EVENT_SOCK_ID 778
#define WIFI_NL80211_CMD_SOCK_ID DEFAULT_NL80211_CMD_SOCK_ID
#define WIFI_NL80211_EVENT_SOCK_ID DEFAULT_NL80211_EVENT_SOCK_ID

#define IEEE80211_ADDR_LEN 6

#define FILE_NAME_LENGTH 64
#define MAX_WIPHY 3
#define MAC_STRING_LENGTH 17

#define streq(a,b) ((strlen(a) == strlen(b)) && (strncasecmp(a,b,sizeof(b)-1) == 0))
#define send_nl_command(sk_ctx, ifname, buf, len, cb, cmd) \
            send_command(sk_ctx, ifname, buf, len, cb, cmd, 0);

typedef enum config_mode_type {
    CONFIG_IOCTL    = 0,
    CONFIG_CFG80211 = 1,
    CONFIG_INVALID  = 2,
} config_mode_type;

struct socket_context {
    u_int8_t cfg80211;
#ifdef EXQCA
#if UMAC_SUPPORT_CFG80211
    wifi_cfg80211_context cfg80211_ctxt;
#endif
#endif
    int sock_fd;
};

extern uint16_t g_stainfo_len;
extern int  _bsal_ioctl_fd;
#ifdef EXQCA
extern uint8_t bsal_clients[IOCTL80211_CLIENTS_SIZE];
#endif

int readcmd(char *buf, size_t buflen, void (*xfrm)(char *), const char *fmt, ...);

int ether_mac2string(char *mac_string, const uint8_t mac[IEEE80211_ADDR_LEN]);
int ether_string2mac(uint8_t mac[IEEE80211_ADDR_LEN], const char *mac_addr);
long long int power (int index, int exponent);
void print_hex_buffer(void *buf, int len);
int start_event_thread (struct socket_context *sock_ctx);
void destroy_socket_context (struct socket_context *sock_ctx);
enum config_mode_type get_config_mode_type();
void osync_peer_stats_event_callback(char *ifname, uint32_t cmdid, uint8_t *data, size_t len);
int forkexec(const char *file, const char **argv, void (*xfrm)(char *), char *buf, int len);
#ifdef EXQCA
int init_socket_context (struct socket_context *sock_ctx, int cmd_sock_id, int event_sock_id);
int send_command (struct socket_context *sock_ctx, const char *ifname, void *buf,
        size_t buflen, void (*callback) (struct cfg80211_data *arg), int cmd, int ioctl_cmd);
#endif

#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 0)
static int qca_bsal_bs_enable(int fd, const char *ifname, bool enable);
void qca_bsal_fill_sta_info(bsal_client_info_t *info, struct ieee80211req_sta_info *sta);

static inline int osync_nl80211_bsal_bs_enable(int fd, const char *ifname, bool enable)
{
    struct ieee80211req_athdbg      athdbg;

    // set band steering
    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_BSTEERING_ENABLE;
    athdbg.data.bsteering_enable = enable;

    send_nl_command(&sock_ctx, ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
    // set band steering events
    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_BSTEERING_ENABLE_EVENTS;
    athdbg.data.bsteering_enable = enable;

    send_nl_command(&sock_ctx, ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
    return 0;
}

static inline int osync_nl80211_bsal_bs_config(int fd, const bsal_ifconfig_t *ifcfg, bool enable)
{
    struct ieee80211req_athdbg      athdbg;
    int                             index;

    // Have to disable before config parameters can be set
    if(qca_bsal_bs_enable(fd, ifcfg->ifname, false) < 0) return -1;

    if (!enable) return(0);

    // Band steering parameters
    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_BSTEERING_SET_PARAMS;
    athdbg.data.bsteering_param.utilization_sample_period         = ifcfg->chan_util_check_sec;
    athdbg.data.bsteering_param.utilization_average_num_samples   = ifcfg->chan_util_avg_count;
    athdbg.data.bsteering_param.inactivity_check_period           = ifcfg->inact_check_sec;
    athdbg.data.bsteering_param.inactivity_timeout_overload       = ifcfg->inact_tmout_sec_overload;
    athdbg.data.bsteering_param.low_rssi_crossing_threshold       = ifcfg->def_rssi_low_xing;
    athdbg.data.bsteering_param.low_rate_rssi_crossing_threshold  = ifcfg->def_rssi_xing;

    for (index = 0; index < BSTEERING_MAX_CLIENT_CLASS_GROUP; index++) {
        athdbg.data.bsteering_param.inactivity_timeout_normal[index]         = ifcfg->inact_tmout_sec_normal;
        athdbg.data.bsteering_param.inactive_rssi_xing_low_threshold[index]  = ifcfg->def_rssi_inact_xing;
        athdbg.data.bsteering_param.inactive_rssi_xing_high_threshold[index] = ifcfg->def_rssi_inact_xing;
        athdbg.data.bsteering_param.high_rate_rssi_crossing_threshold[index] = ifcfg->def_rssi_xing;
        // Needed to satisfy parameter validation
        athdbg.data.bsteering_param.high_tx_rate_crossing_threshold[index]  = 1;
    }
    send_nl_command(&sock_ctx, ifcfg->ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);

    // Band steering debug parameters
    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_BSTEERING_SET_DBG_PARAMS;
    athdbg.data.bsteering_dbg_param.raw_chan_util_log_enable    = ifcfg->debug.raw_chan_util;
    athdbg.data.bsteering_dbg_param.raw_rssi_log_enable         = ifcfg->debug.raw_rssi;

    send_nl_command(&sock_ctx, ifcfg->ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);

    return qca_bsal_bs_enable(fd, ifcfg->ifname, true);
}

static inline int osync_nl80211_bsal_acl_mac(int fd, const char *ifname, const uint8_t *mac_addr, bool add)
{
    struct sockaddr saddr;
    int cno = add ? QCA_NL80211_VENDORSUBCMD_ADDMAC : QCA_NL80211_VENDORSUBCMD_DELMAC;

    memset(&saddr, 0, sizeof(saddr));
    memcpy(&saddr.sa_data, mac_addr, BSAL_MAC_ADDR_LEN);
    send_nl_command(&sock_ctx, ifname, &saddr, BSAL_MAC_ADDR_LEN, NULL, cno);

    return 0;
}

static inline int osync_nl80211_bsal_bs_client_config(int fd, const char *ifname, const uint8_t *mac_addr,
                                    const bsal_client_config_t *conf)
{
    struct ieee80211req_athdbg      athdbg;
    int                             ret = 0;

    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_ACL_SET_CLI_PARAMS;
    memcpy(&athdbg.dstmac, mac_addr, sizeof(athdbg.dstmac));

    athdbg.data.acl_cli_param.probe_rssi_hwm       = conf->blacklist ? 1 : conf->rssi_probe_hwm;
    athdbg.data.acl_cli_param.probe_rssi_lwm       = conf->rssi_probe_lwm;

    athdbg.data.acl_cli_param.auth_rssi_hwm        = conf->rssi_auth_hwm;      // Set HWM here for Auth pkts
    athdbg.data.acl_cli_param.auth_rssi_lwm        = conf->rssi_auth_lwm;      // Set LWM here for Auth pkts
    athdbg.data.acl_cli_param.auth_reject_reason   = conf->auth_reject_reason; // 0 = drop, > 0 = reject reason code

    athdbg.data.acl_cli_param.inact_rssi_xing      = conf->rssi_inact_xing;
    athdbg.data.acl_cli_param.low_rssi_xing        = conf->rssi_low_xing;
    athdbg.data.acl_cli_param.high_rate_rssi_xing  = conf->rssi_high_xing;
    athdbg.data.acl_cli_param.low_rate_rssi_xing   = conf->rssi_high_xing;

    send_nl_command(&sock_ctx, ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);

    return ret;
}

#ifdef EXQCA
static inline void bsal_stainfo_cb(struct cfg80211_data *buffer)
{
    uint32_t    len = buffer->length;

    if (len < sizeof(struct ieee80211req_sta_info)) return;

    memcpy((bsal_clients + g_stainfo_len), buffer->data, len);
    g_stainfo_len += len;
}

static inline int qca_bsal_client_stats(const char *ifname, const uint8_t *mac_addr, bsal_client_info_t *info)
{
    struct ieee80211req_sta_stats stats = {0};
    const struct ieee80211_nodestats *ns = &stats.is_stats;
    struct cfg80211_data            buffer;
    int                             msg;

    memcpy(stats.is_u.macaddr, mac_addr, IEEE80211_ADDR_LEN);

    buffer.data = (uint8_t *)&stats;
    buffer.length = sizeof(stats);
    buffer.callback = NULL;
    buffer.parse_data = 0;
    msg = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_STA_STATS,
            ifname, (char *)&buffer, LIST_STATION_CFG_ALLOC_SIZE);
    if (msg < 0) {
        LOGE("%s: Unable to get STA Stats", ifname);
        return -1;
    }
    info->tx_bytes = ns->ns_tx_bytes;
    info->rx_bytes = ns->ns_rx_bytes;

    return 0;
}

static inline int osync_nl80211_sta_info(const char *ifname, const uint8_t *mac_addr, bsal_client_info_t *info)
{
    struct ieee80211req_sta_info    *sta;
    uint32_t                        len;
    uint8_t                         *buf, *p;
    uint8_t                         *assoc_ies;
    uint16_t                        assoc_ies_len;
    bool                            found = false;
    struct cfg80211_data            buffer;
    int                             rc;
    uint8_t                         *buf_tmp;

    memset(info, 0, sizeof(*info));
    g_stainfo_len = 0;
    memset (bsal_clients, 0, sizeof(bsal_clients));
    buf_tmp = (uint8_t *) malloc(LIST_STATION_CFG_ALLOC_SIZE);
    if (!buf_tmp) {
        LOGI("%s: Unable to allocate memory for station list", __func__);
        return IOCTL_STATUS_ERROR;
    }

    buffer.data         = buf_tmp;
    buffer.length       = LIST_STATION_CFG_ALLOC_SIZE;
    buffer.callback     = &bsal_stainfo_cb;
    buffer.parse_data   = 0;
    rc = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_LIST_STA, ifname,
            (char *)&buffer, buffer.length);
    if (0 > rc) {
        free(buf_tmp);
        LOG(ERR,
            "Parsing %s client stats (Failed to get info '%s')",
            ifname,
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    len = g_stainfo_len;
    LOGI("%s: length - %u", __func__, len);
    buf = bsal_clients;
    free(buf_tmp);

    p = buf;
    while(len >= sizeof(*sta)) {
        sta = (struct ieee80211req_sta_info *)p;

        if(memcmp(sta->isi_macaddr, mac_addr, sizeof(sta->isi_macaddr)) == 0) {
            found = true;
            break;
        }

        len -= sta->isi_len;
        p   += sta->isi_len;
    }

    if (found) {
        // fill station info
        qca_bsal_fill_sta_info(info, sta);
        qca_bsal_client_get_datarate_info(ifname, mac_addr, &info->datarate_info);
        info->connected = true;

        assoc_ies_len = sta->isi_len - sizeof(*sta);
        assoc_ies = (uint8_t *) (sta+1);
        if (assoc_ies_len <= sizeof(info->assoc_ies)) {
            memcpy(info->assoc_ies, assoc_ies, assoc_ies_len);
            info->assoc_ies_len = assoc_ies_len;
        } else {
            LOGW("%s ies_len (%u) higher than ies table (%zu)", ifname, assoc_ies_len, sizeof(info->assoc_ies));
        }
    }

    if (info->connected)
        qca_bsal_client_stats(ifname, mac_addr, info);

    return 0;
}
#endif

static inline int osync_nl80211_bsal_client_measure(const char *ifname, const uint8_t *mac_addr, int num_samples)
{
    struct ieee80211req_athdbg      athdbg;

    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_BSTEERING_GET_RSSI;
    memcpy(&athdbg.dstmac, mac_addr, sizeof(athdbg.dstmac));
    athdbg.data.bsteering_rssi_num_samples = num_samples;

    return send_nl_command(&sock_ctx, ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
}

#endif
#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 2)

#ifdef EXQCA
# define strdupa(s)                                    \
  (__extension__                                       \
    ({                                                 \
      const char *__old = (s);                         \
      size_t __len = strlen (__old) + 1;               \
      char *__new = (char *) __builtin_alloca (__len); \
      (char *) memcpy (__new, __old, __len);           \
    }))
#endif

#include <string.h>
#include "util.h"

static inline int osync_nl80211_init(struct ev_loop *loop)
{
    int err = 0;
    pid_t pid;
    char buf[256];
    char buffer[64];

    pid = getpid();

    memset(&sock_ctx, 0, sizeof(struct socket_context));
    snprintf(buf, sizeof(buf), "ps | grep %d", pid);
    err = readcmd(buffer, sizeof(buffer), 0, "%s", buf);
    if (err) {
        LOGI("Unable to get process name using pid %d\n", pid);
    }
#ifdef EXQCA
    if (strstr(buffer, "sm")) {
        sock_ctx.cfg80211_ctxt.event_callback = osync_peer_stats_event_callback;
    }

    sock_ctx.cfg80211 = 1;
    err = init_socket_context(&sock_ctx, WIFI_NL80211_CMD_SOCK_ID, WIFI_NL80211_EVENT_SOCK_ID);
    if (err) {
        return -EIO;
    }
    if (strstr(buffer, "sm")) {
        if (wifi_nl80211_start_event_thread(&sock_ctx.cfg80211_ctxt)) {
            wifi_destroy_nl80211(&sock_ctx.cfg80211_ctxt);
            return -EIO;
        }
    }
#endif
    return IOCTL_STATUS_OK;
}

static inline int osync_nl80211_close(struct ev_loop *loop)
{
#ifdef EXQCA
    destroy_socket_context(&sock_ctx);
#endif
    return IOCTL_STATUS_OK;
}

#ifdef EXQCA
static int send_get_command(const char *ifname, void *buf, size_t buflen, int cmd)
{
    int msg;
    struct cfg80211_data buffer;
    if (sock_ctx.cfg80211) {
        buffer.data = buf;
        buffer.length = buflen;
        buffer.callback = NULL;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_getparam_command(&(sock_ctx.cfg80211_ctxt),
                    cmd, 0,
                    ifname, (char *)&buffer, buflen);
        if (msg < 0) {
            LOG(ERR,"Could not send NL command get bssid failed");
            return -1;
        }
        return buffer.length;
    }
    return -1;
}
#endif

static ioctl_status_t ioctl80211_radio_type_get(char *ifName, radio_type_t *type);
void rtrimnl(char *str);
void rtrimws(char *str);

static int util_iwconfig_get_opmode(const char *device_vif_ifname, unsigned int *opmode, int len)
{
#ifdef EXQCA
    int msg = -1;
    struct cfg80211_data buffer;

    memset(opmode, 0, len);

    if (sock_ctx.cfg80211) {
        buffer.data = opmode;
        buffer.length = sizeof(opmode);
        buffer.callback = NULL;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_getparam_command(&(sock_ctx.cfg80211_ctxt),
                  QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, IEEE80211_PARAM_GET_OPMODE,
                    device_vif_ifname, (char *)&buffer,
                    sizeof(uint32_t));
        if (msg < 0) {
            LOG(ERR,"Could not send NL command for get opmode");
            return -1;
        }
    }

#endif
    return 0;
}

static inline int osync_nl80211_interfaces_get(int sock_fd, char *ifname, char *args[], int radio_type)
{
    ioctl_status_t          status;
    struct iwreq            request;
    int                     mode = 0;
    unsigned int            opmode;
    ioctl80211_interface_t  *interface = NULL;
    ioctl80211_interfaces_t *interfaces = (ioctl80211_interfaces_t *) args[IOCTL80211_IFNAME_ARG];

    interface = &interfaces->phy[interfaces->qty];
    STRSCPY(interface->ifname, ifname);
    memset (&request, 0, sizeof(request));

    util_iwconfig_get_opmode(interface->ifname, &opmode, sizeof(opmode));
#ifdef EXQCA
    if (opmode == IEEE80211_M_HOSTAP)
        mode = IW_MODE_MASTER;
    else
        mode = IW_MODE_INFRA;
#endif
    interface->sta = false;

    switch (mode)
    {
        case IW_MODE_INFRA:
            interface->sta = true;
            break;
        case IW_MODE_MASTER:
            break;
        default:
            LOG(TRACE,
                "Skip processing non wireless interface %s",
                interface->ifname);
            return IOCTL_STATUS_OK;
    }

#ifdef EXQCA
    send_get_command(interface->ifname, interface->mac, IEEE80211_ADDR_LEN,
                QCA_NL80211_VENDORSUBCMD_BSSID);
    LOGD("osync_nl80211_interfaces_get bssid:%x:%x:%x:%x:%x:%x ifname:%s",
                interface->mac[0],interface->mac[1],interface->mac[2],
                interface->mac[3],interface->mac[4],interface->mac[5],
                interface->ifname);
#endif
    const mac_address_t zero[] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    if (!memcmp(interface->mac, zero, sizeof(mac_address_t)))
    {
        LOG(TRACE,
            "Skip processing non associated interface %s",
            interface->ifname);
        return IOCTL_STATUS_OK;
    }

    memset (interface->essid, 0, sizeof(interface->essid));
#ifdef EXQCA
    send_nl_command(&sock_ctx, ifname, interface->essid, sizeof(interface->essid),
                NULL, QCA_NL80211_VENDORSUBCMD_GET_SSID);
    LOGD("osync_nl80211_interfaces_get ssid :%s", interface->essid);
#endif

    if (!strlen(interface->essid))
    {
        LOG(ERR,
            "Skip processing non defined radio phy %s",
            interface->ifname);
        return IOCTL_STATUS_ERROR;
    }

    status =
        ioctl80211_radio_type_get(
                interface->ifname,
                &interface->radio_type);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    if ((radio_type_t)radio_type != interface->radio_type)
    {
        LOG(TRACE,
            "Skip processing %s radio interface %s",
            radio_get_name_from_type(interface->radio_type),
            interface->ifname);
        return IOCTL_STATUS_OK;
    }

    LOG(TRACE,
        "Parsed %s radio %s interface %s MAC='"MAC_ADDRESS_FORMAT"' SSID='%s'",
        radio_get_name_from_type(radio_type),
        interface->sta ? "STA" : "AP",
        interface->ifname,
        MAC_ADDRESS_PRINT(interface->mac),
        interface->essid);

    interfaces->qty++;

    return IOCTL_STATUS_OK;
}

static inline int osync_nl80211_radio_type_get(char *ifName, radio_type_t *type)
{
    char *line;
    int c;
    bool has_upper = false;
    bool has_lower = false;
    bool has_24g = false;
    char *chan;
    char *keyword = NULL;
    char *buf = NULL;
    char cmd[128];
    const char *phy = NULL;

    snprintf(cmd, sizeof(cmd), "/sys/class/net/%s/parent", ifName);
    phy = strexa("cat", cmd) ?: "0";
    buf = strexa("exttool", "--interface", phy, "--list");
    if (!buf)
        return IOCTL_STATUS_ERROR;

    while ((line = strsep(&buf, "\n"))) {
        if (!(keyword = strsep(&line, " ")))
            continue;
        if (!(chan = strsep(&line, " ")))
            continue;

        c = atoi(chan);
        if(c < 100)
            has_lower = true;
        if(c > 100)
            has_upper = true;

        if (c >= 1 && c <= 20)
            has_24g = true;

        if (has_24g) {
            *type = RADIO_TYPE_2G;
            break;
        }
        else if (has_upper && has_lower) {
            *type = RADIO_TYPE_5G;
        }
        else if (has_lower) {
            *type = RADIO_TYPE_5GL;
        }
        else if (has_upper) {
            *type = RADIO_TYPE_5GU;
        } else {
            LOG(ERR,"Parsing %s radio type (Invalid type)", phy);
            return IOCTL_STATUS_ERROR;
        }
    }
#if 0
    char buf[64];
    if (WARN(-1 == util_exec_read(rtrimnl, buf, sizeof(buf),
                        "cfg80211tool", ifName, "get_mode"),
                        "%s: failed to get cfg80211tool '%s': %d (%s)",
                        ifName, "get_mode", errno, strerror(errno))) {
        return -1;
    }

    LOG(ERR, "buf val:%s\n", buf);

    if ((NULL != strstr(buf, "a"))
        ||  (NULL != strstr(buf, "a"))
        ||      (NULL != strstr(buf, "a"))
        ) {
    struct ieee80211req_chaninfo    chaninfo;
    int list_alloc_size = 3*1024;
    const typeof(chaninfo.ic_chans[0]) *chan;
    uint32_t                        channel;

    LOG(ERR,"inside if:%d\n",5);
    memset (&chaninfo, 0, sizeof(chaninfo));
    send_nl_command(&sock_ctx, ifName, &chaninfo, list_alloc_size,
                NULL, QCA_NL80211_VENDOR_SUBCMD_LIST_CHAN);
#endif
    return IOCTL_STATUS_OK;
}

static inline int osync_nl80211_get_essid(int sock_fd, const char *ifname, char *dest, int dest_len)
{
#ifdef EXQCA
    send_nl_command(&sock_ctx, ifname, dest, dest_len, NULL, QCA_NL80211_VENDORSUBCMD_GET_SSID);
    LOG(ERR, "osync_nl80211_get_essid :%s", dest);
#endif
    return IOCTL_STATUS_OK;
}
#endif

#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 3)
extern struct socket_context sock_ctx;

static int util_qca_set_int(const char *ifname, const char *iwprivname, int v)
{
    char arg[16];
    char command[32] = "--";
    strcat(command,iwprivname);

    const char *argv[] = { "cfg80211tool.1", "-i", ifname, "-h", "none", "--START_CMD", command, "--value0", arg,
                           "--RESPONSE", command, "--END_CMD", NULL };
    char c;

    snprintf(arg, sizeof(arg), "%d", v);
    return forkexec(argv[0], argv, NULL, &c, sizeof(c));
}

static inline int osync_nl80211_ioctl80211_radio_tx_stats_enable(radio_entry_t *radio_cfg, bool status)
{
    util_qca_set_int(radio_cfg->phy_name, "enable_ol_stats", status ? 1 : 0);
#if 0
    /*
     * The issue specific to "disablestats" command is fixed in
     * the driver so this code is not required.
     */
    util_qca_set_int(radio_cfg->phy_name, "disablestats", status ? 0 : 1);
#endif
    util_qca_set_int(radio_cfg->phy_name, "enable_statsv2", status ? 0xf : 0);
    return IOCTL_STATUS_OK;
}

static inline void osync_nl80211_ioctl80211_radio_stats_set_iwparam(radio_entry_t *radio_cfg, ifname_t if_name)
{
#if 0
    /*
     * The issue specific to "disablestats" command is fixed in
     * the driver so this code is not required.
     */
    util_qca_set_int(if_name, "srssicombfix", 3); //implement in tool
#endif
    util_qca_set_int(if_name, "suniformrssi", 1);
}

#ifdef EXQCA
static int
osync_nl80211_fast_scan_enable(const char *ifname, struct ieee80211req_athdbg  *athdbg)
{
    send_nl_command(&sock_ctx, ifname, athdbg, sizeof(struct ieee80211req_athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
    return 0;
}
#endif
#endif

#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 1)
extern struct socket_context sock_ctx;

#ifdef EXQCA
static inline int osync_nl80211_clients_stats_fetch (
        radio_type_t                radio_type,
        char                       *ifName,
        ioctl80211_client_record_t *client_entry,
        struct ieee80211req_sta_stats *ieee80211_client_stats)
{
    int rc = 0;

    memset (ieee80211_client_stats, 0, sizeof(struct ieee80211req_sta_stats));
    memcpy (ieee80211_client_stats->is_u.macaddr,
            client_entry->info.mac,
            sizeof(ieee80211_client_stats->is_u.macaddr));

    send_nl_command(&sock_ctx, ifName, ieee80211_client_stats, sizeof(struct ieee80211req_sta_stats), NULL,
                QCA_NL80211_VENDOR_SUBCMD_STA_STATS);

    return rc;
}

static inline int osync_nl80211_peer_stats_fetch(char *ifName, struct ioctl80211_vap_stats *vap_stats)
{
    int rc = 0;

    send_nl_command(&sock_ctx, ifName, vap_stats,
                    sizeof(struct ioctl80211_vap_stats), NULL,
                    QCA_NL80211_VENDOR_SUBCMD_80211STATS);

    return rc;
}
#endif
#endif

#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 4)
void rtrimws(char *str);

static inline bool qca_get_int(const char *ifname, const char *iwprivname, int *v)
{
    char *p;
    char command[32] = "--";
    strcat(command, iwprivname);
    const char *argv[] = { "cfg80211tool.1", "-i", ifname, "-h", "none", "--START_CMD", command, "--RESPONSE", command,
                            "--END_CMD", NULL };
    char buf[128];
    int err;

    err = forkexec(argv[0], argv, rtrimws, buf, sizeof(buf));
    if (err < 0)
        return false;
    p = strchr(buf, ':');
    if (!p)
        return false;

    p++;
    if (strlen(p) == 0)
        return false;

    *v = atoi(p);
    LOGD("get value:%d\n",*v);
    return true;
}

static inline int nl80211_device_txchainmask_get(radio_entry_t *radio_cfg, dpp_device_txchainmask_t   *txchainmask)
{
    int32_t rc;
    int txchain_type;

    rc = qca_get_int(radio_cfg->phy_name, "get_txchainmask", &txchain_type);
    if (!rc) {
        LOGW("%s: failed to get iwpriv int '%s'",
             radio_cfg->phy_name, "get_txchainmask");
        return -1;
    }

    txchainmask->type = radio_cfg->type;
    txchainmask->value = txchain_type;

    return IOCTL_STATUS_OK;
}
#endif

#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 5)
#define QCA_NL80211_VENDOR_SUBCMD_TRIGGER_SCAN 106
#define QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION 74
extern struct socket_context sock_ctx;

#ifdef EXQCA
int send_scan_req(struct socket_context *sock_ctx, const char *ifname, void *buf,
        size_t buflen, void (*callback) (struct cfg80211_data *arg), int cmd)
{
    int msg = -1;
    struct cfg80211_data buffer;
    if (sock_ctx->cfg80211) {
        buffer.data = buf;
        buffer.length = buflen;
        buffer.callback = callback;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_generic_command(&(sock_ctx->cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_TRIGGER_SCAN,
                cmd, ifname, (char *)&buffer, buflen);
        if (msg < 0) {
            LOG(ERR,"Could not send NL scan command");
            return -1;
        }
        return buffer.length;
    }
    return 0;
}

static void  bss_info_handler(struct cfg80211_data *buffer)
{
    memcpy(g_iw_scan_results + res_len, buffer->data,buffer->length);
    res_len += buffer->length;
    g_iw_scan_results_size += buffer->length;
}

static inline int osync_nl80211_scan_results_fetch(radio_entry_t *radio_cfg_ctx)
{
    int msg = -1;
    int list_alloc_size;
    list_alloc_size = 3*1024;
    struct cfg80211_data buffer;
    uint8_t *buf = malloc(list_alloc_size);

    buffer.data = buf;
    buffer.length = list_alloc_size;
    buffer.callback = bss_info_handler;
    buffer.parse_data = 0;

    msg = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_LIST_SCAN, radio_cfg_ctx->if_name, (char *)&buffer, list_alloc_size);
    if (msg < 0) {
        LOG(ERR,"Failed to send NL scan command");
        return -1;
    }

    free(buf);
    return buffer.length;
}
#endif

static inline int
osync_nl80211_scan_channel(char *ifname, struct iw_scan_req *iw_scan_options ,int iw_scan_flags)
{
    int rc = -1;
#ifdef EXQCA
    rc = send_scan_req(&sock_ctx, ifname, iw_scan_options, sizeof(struct iw_scan_req), NULL, 0);
#endif

    return rc;
}
#endif
#endif /* IOCTL80211_NETLINK_11AX_H_INCLUDED */
