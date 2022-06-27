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
#include <stdio.h>
#include <stdbool.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include "target.h"
#include "hostapd_util.h"
#include "wiphy_info.h"
#include "log.h"
#include "ds_dlist.h"

#include "wpa_ctrl.h"

#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <linux/netlink.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "os_random.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"

/* See target_radio_config_init2() for details */
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"

#include "bsal.h"

#include <linux/un.h>
#include <opensync-ctrl.h>
#include <opensync-wpas.h>
#include <opensync-hapd.h>

#include "target_cfg80211.h"
#include "target_util.h"
#include "nl80211.h"
#include "kconfig.h"
#include "opensync-ctrl-dpp.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

/******************************************************************************
 * Driver-dependant feature compatibility
 *****************************************************************************/

/******************************************************************************
 * GLOBALS
 *****************************************************************************/

#define HOME_AP_PREFIX  "home-ap"
#define HOME_AP_24      "home-ap-24"
#define BHAUL_AP_24     "bhaul-ap-24"
#define ONBOARD_AP_24   "onboard-ap-24"
#define IFNAME_TYPE_AP  "-ap-"
#define IFNAME_TYPE_STA "-sta-"

#define UTIL_CB_PHY         "phy"
#define UTIL_CB_VIF         "vif"
#define UTIL_CB_KV_KEY      "delayed_update_ifname_list"
#define UTIL_CB_DELAY_SEC   1

struct nl_global_info   target_nl_global;
static ev_timer         g_util_cb_timer;
void target_nl80211_deinit(struct nl_global_info *nl_global);

static int      util_nl_fd = -1;
static ev_io    util_nl_io;

struct util_wpa_ctrl_watcher {
    ev_io io;
    char sockpath[128];
    char phy[32];
    char vif[32];
    struct wpa_ctrl *ctrl;
    struct ds_dlist_node list;
};

struct kvstore {
    struct ds_dlist_node list;
    char key[64];
    char val[512];
};

struct fallback_parent {
    int channel;
    char bssid[18];
};

static ds_dlist_t g_kvstore_list = DS_DLIST_INIT(struct kvstore, list);

static struct target_radio_ops rops;

/* See target_radio_config_init2() for details */
static struct schema_Wifi_Radio_Config *g_rconfs;
static struct schema_Wifi_VIF_Config *g_vconfs;
ovsdb_table_t table_Wifi_Radio_Config;
ovsdb_table_t table_Wifi_VIF_Config;
static int g_num_rconfs;
static int g_num_vconfs;

struct channel_status g_chan_status[IEEE80211_CHAN_MAX];

static bool util_radio_country_get(const char *phy, char *country, int country_len);

/******************************************************************************
 * Generic helpers
 *****************************************************************************/

void
rtrimnl(char *str)
{
    int len;
    len = strlen(str);
    while (len > 0 && (str[len-1] == '\r' || str[len-1] == '\n'))
        str[--len] = 0;
}

void
rtrimws(char *str)
{
    int len;
    len = strlen(str);
    while (len > 0 && isspace(str[len - 1]))
        str[--len] = 0;
}

int
readcmd(const char *fmt, ...)
{
    char cmd[1024];
    va_list ap;
    int err;

    memset(cmd, 0, sizeof(cmd));
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);

    LOGT("%s: fmt(%s) => %s", __func__, fmt, cmd);

    err = system(cmd);
    LOGT("%s: err => %d, errno => %d", __func__, err, errno);

    return err;
}

void
argv2str(const char **argv, char *buf, int len)
{
    int i;

    memset(buf, 0, len);
    len -= 1; /* for NUL */

    strncat(buf, "[", len - strlen(buf));
    for (i = 0; argv[i]; i++) {
        strncat(buf, argv[i], len - strlen(buf));
        if (argv[i+1])
            strncat(buf, ",", len - strlen(buf));
    }
    strncat(buf, "]", len - strlen(buf));
}

int
forkexec(const char *file, const char **argv, void (*xfrm)(char *), char *buf, int len)
{
    char dbgbuf[512];
    int status;
    int io[2];
    int pid;
    int off;
    int err;
    char of;
    char c;

    if (!buf) {
        buf = &c;
        len = sizeof(c);
    }

    err = pipe(io);
    if (err < 0)
        return err;

    buf[0] = 0;
    len--; /* for NUL */
    argv2str(argv, dbgbuf, sizeof(dbgbuf));

    pid = fork();
    switch (pid) {
        case 0:
            close(0);
            close(1);
            close(2);
            dup2(io[1], 1);
            close(io[0]);
            close(io[1]);
            execvp(file, (char **)argv);
            exit(1);
        case -1:
            close(io[0]);
            close(io[1]);
            err = -1;
            LOGT("%s: %s: fork failed: %d (%s)",
                 __func__, dbgbuf, errno, strerror(errno));
            break;
        default:
            close(io[1]);
            off = 0;
            while (off < len) {
                err = read(io[0], buf + off, len - off);
                if (err <= 0)
                    break;
                off += err;
            }
            while (read(io[0], &of, 1) == 1) /* NOP */;
            buf[off] = 0;
            close(io[0]);
            waitpid(pid, &status, 0);

            err = -1;
            if (WIFEXITED(status)) {
                errno = WEXITSTATUS(status);
                if (!errno)
                    err = 0;
            }

            if (xfrm)
                xfrm(buf);

            LOGT("%s: %s: '%s' (%d), %d (%s)",
                 __func__, dbgbuf, buf, off, errno, strerror(errno));
            break;
    }

    return err;
}

static int
util_file_read(const char *path, char *buf, int len)
{
    int fd;
    int err;
    int errno2;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    err = read(fd, buf, len);
    errno2 = errno;
    close(fd);
    errno = errno2;
    return err;
}

static int
util_file_write(const char *path, const char *buf, int len)
{
    int fd;
    int err;
    int errno2;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    err = write(fd, buf, len);
    errno2 = errno;
    close(fd);
    errno = errno2;
    return err;
}

static int
util_file_read_str(const char *path, char *buf, int len)
{
    int rlen;
    buf[0] = 0;
    rlen = util_file_read(path, buf, len);
    if (rlen < 0)
        return rlen;
    buf[rlen] = 0;
    LOGT("%s: '%s' (%d)", path, buf, rlen);
    return rlen;
}

static int
util_exec_scripts(const char *vif)
{
    int err;
    char cmd[512];

    /* FIXME: target_scripts_dir() points to something
     *        different than on WM1. This needs to be
     *        killed fast!
     */
    LOGI("%s: running hook scripts", vif);
    sprintf(cmd, "{ cd %s/wm.d 2>/dev/null || cd %s/../scripts/wm.d 2>/dev/null; } && for i in *.sh; do sh $i %s; done; exit 0",
                 target_bin_dir(),
                 target_bin_dir(),
                 vif);

    err = system(cmd);
    if (err) {
        LOGW("%s: failed to run command", vif);
        return err;
    }

    return 0;
}

static void
util_ovsdb_wpa_clear(const char *if_name)
{
    ovsdb_table_t table_Wifi_VIF_Config;
    struct schema_Wifi_VIF_Config new_vconf;
    int ret;

    OVSDB_TABLE_INIT(Wifi_VIF_Config, if_name);
    memset(&new_vconf, 0, sizeof(new_vconf));
    new_vconf._partial_update = true;
    new_vconf.wps_pbc_exists = false;
    new_vconf.wps_pbc_present = true;

    ret = ovsdb_table_update_simple(&table_Wifi_VIF_Config, strdupa(SCHEMA_COLUMN(Wifi_VIF_Config, if_name)),
            strdupa(if_name), &new_vconf);

    if (ret)
        LOGD("wps: Unset Wifi_VIF_Config:wps_pbc on iface: %s after starting WPS session", if_name);
    else
        LOGW("wps: Failed to unset Wifi_VIF_Config:wps_pbc on iface: %s", if_name);
}

int ht_mode_to_bw(const struct schema_Wifi_Radio_Config *rconf, int *width)
{
    const char *width_ptr;

    if (!rconf->ht_mode_exists) return -EINVAL;

    width_ptr = strlen(rconf->ht_mode) > 2 ? (rconf->ht_mode + 2) : "20";
    *width = atoi(width_ptr);

    return 0;
}

void ht_mode_to_mode(const struct schema_Wifi_Radio_Config *rconf, char *mode, int mode_len)
{
    if (!rconf->hw_mode_exists) return;

    if (!strcmp(rconf->hw_mode, "11ac"))
        strscpy(mode, "ht vht", mode_len);
    if (!strcmp(rconf->hw_mode, "11n"))
        strscpy(mode, "ht", mode_len);

    return;
}

int get_sec_chan_offset(const struct schema_Wifi_Radio_Config *rconf)
{
    if (!strcmp(rconf->ht_mode, "HT40")
        || !strcmp(rconf->ht_mode, "HT80")
        || !strcmp(rconf->ht_mode, "HT160")) {
        switch (rconf->channel) {
            case 1 ... 7:
            case 36:
            case 44:
            case 52:
            case 60:
            case 100:
            case 108:
            case 116:
            case 124:
            case 132:
            case 140:
            case 149:
            case 157:
                return 1;
            case 8 ... 13:
            case 40:
            case 48:
            case 56:
            case 64:
            case 104:
            case 112:
            case 120:
            case 128:
            case 136:
            case 144:
            case 153:
            case 161:
                return -1;
            default:
                return -EINVAL;
        }
    }

    return -EINVAL;
}

char *chan_state_to_str(enum channel_state state)
{
    switch (state) {
        case ALLOWED:
            return "ALLOWED";
        case CAC_STARTED:
            return "CAC_STARTED";
        case CAC_COMPLETED:
            return "CAC_COMPLETED";
        case NOP_STARTED:
            return "NOP_STARTED";
        case NOP_FINISHED:
            return "NOP_FINISHED";
        default:
            return "INVALID";
    }
}

int get_chanlist_cfreq(const int *chanlist)
{
    int sum = 0;
    int cnt = 0;

    if (!chanlist)
        return 0;

    while (*chanlist) {
        sum += *chanlist;
        cnt++;
        chanlist++;
    }
    return sum / cnt;
}

const int *dfs_get_chanlist_from_centerchan(const int channel, const int centerchan)
{
    const int *chanlist;

    chanlist = unii_5g_chan2list(channel, 20);
    if (centerchan == get_chanlist_cfreq(chanlist))
        return chanlist;

    chanlist = unii_5g_chan2list(channel, 40);
    if (centerchan == get_chanlist_cfreq(chanlist))
        return chanlist;

    chanlist = unii_5g_chan2list(channel, 80);
    if (centerchan == get_chanlist_cfreq(chanlist))
        return chanlist;

    return NULL;
}

/******************************************************************************
 * Key-value store
 *****************************************************************************/

static struct kvstore *
util_kv_get(const char *key)
{
    struct kvstore *i;
    ds_dlist_foreach(&g_kvstore_list, i)
        if (!strcmp(i->key, key))
            return i;
    return NULL;
}

static void
util_kv_set(const char *key, const char *val)
{
    struct kvstore *i;

    if (!key)
        return;

    if (!(i = util_kv_get(key))) {
        if (!(i = malloc(sizeof(*i))))
            return;
        else
            ds_dlist_insert_tail(&g_kvstore_list, i);
    }

    if (!val) {
        ds_dlist_remove(&g_kvstore_list, i);
        free(i);
        LOGT("%s: '%s'=nil", __func__, key);
        return;
    }

    STRSCPY(i->key, key);
    STRSCPY(i->val, val);
    LOGT("%s: '%s'='%s'", __func__, key, val);
}

static int
util_kv_get_fallback_parents(const char *phy, struct fallback_parent *parent, int size)
{
    const struct kvstore *kv;
    char bssid[32];
    char *line;
    char *buffer;
    int channel;
    int num;

    memset(parent, 0, sizeof(*parent) * size);
    num = 0;

    if (!phy)
        return num;

    kv = util_kv_get(F("%s.fallback_parents", phy));
    if (!kv)
        return num;

    /* We need buffer copy because of strsep() */
    buffer = strdup(kv->val);
    if (!buffer)
        return num;

    while ((line = strsep(&buffer, ",")) != NULL) {
        if (sscanf(line, "%d %18s", &channel, bssid) != 2)
            continue;

        LOGT("%s: parsed fallback parent kv: %d/%d: %s %d", phy, num, size, bssid, channel);
        if (num >= size)
            break;

        parent[num].channel = channel;
        strscpy(parent[num].bssid, bssid, sizeof(parent[num].bssid));
        num++;
    }
    free(buffer);

    return num;
}

static void util_kv_radar_get(const char *phy, struct schema_Wifi_Radio_State *rstate)
{
    char chan[32];
    const char *path;
    struct stat st;

    path = F("/tmp/.%s.radar.detected", phy);

    if (util_file_read_str(path, chan, sizeof(chan)) < 0)
        return;

    if (strlen(chan) == 0)
        return;

    if (stat(path, &st)) {
        LOGW("%s: stat(%s) failed: %d (%s)", phy, path, errno, strerror(errno));
        return;
    }

    SCHEMA_KEY_VAL_APPEND(rstate->radar, "last_channel", chan);
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "num_detected", "1");
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "time", F("%u", (unsigned int) st.st_mtim.tv_sec));
}

static void util_kv_radar_set(const char *phy, const unsigned char chan)
{
    const char *buf;
    const char *path;

    buf = F("%u", chan);
    path = F("/tmp/.%s.radar.detected", phy);

    if (util_file_write(path, buf, strlen(buf)) < 0)
        LOGW("%s: write(%s) failed: %d (%s)", phy, path, errno, strerror(errno));
}

/******************************************************************************
 * Networking helpers
 *****************************************************************************/

static bool
util_net_ifname_exists(const char *ifname, int *v)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", ifname);
    *v = 0 == access(path, X_OK);
    return true;
}

static bool
util_net_phy_exists(const char *phy, int *v)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/ieee80211/%s", phy);
    *v = 0 == access(path, X_OK);
    return true;
}

static int
util_net_get_phy_macaddr_str(const char *phy, char *buf, int len)
{
    char path[128];
    int err;
    snprintf(path, sizeof(path), "/sys/class/ieee80211/%s/addresses", phy);
    err = util_file_read_str(path, buf, len);
    if (err > 0)
        err = 0;
    rtrimws(buf);
    return err;
}

static int
util_net_get_macaddr_str(const char *ifname, char *buf, int len)
{
    char path[128];
    int err;
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
    err = util_file_read_str(path, buf, len);
    if (err > 0)
        err = 0;
    rtrimws(buf);
    return err;
}

static int
util_net_get_macaddr(const char *ifname,
                     char *macaddr)
{
    char buf[32];
    int err;
    int n;

    memset(macaddr, 0, 6);

    if (!strncmp(ifname, CONFIG_MAC80211_WIPHY_PREFIX, strlen(CONFIG_MAC80211_WIPHY_PREFIX)))
        err = util_net_get_phy_macaddr_str(ifname, buf, sizeof(buf));
    else
        err = util_net_get_macaddr_str(ifname, buf, sizeof(buf));
    if (err) {
        LOGW("%s: failed to get mac address: %d (%s)",
             ifname, errno, strerror(errno));
        return err;
    }

    n = sscanf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
               &macaddr[0], &macaddr[1], &macaddr[2],
               &macaddr[3], &macaddr[4], &macaddr[5]);
    if (n != 6) {
        LOGW("%s: failed to parse mac address (%s): %d (%s)",
             ifname, buf, errno, strerror(errno));
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/******************************************************************************
 * Wireless helpers
 *****************************************************************************/

static bool
util_wifi_is_ap_vlan(const char *ifname)
{
    return strstr(ifname, ".sta") != NULL;
}

/* Fetch all phy VIFs of the type(ap/sta) specified */
static int
util_wifi_get_all_phy_vif_type(const char *phy, char *buf, int len, char *type)
{
    struct dirent *p;
    char phy_path[BFR_SIZE_128];
    DIR *d;
    char *phy_name;

    memset(buf, 0, len);

    if (!type)
        return -1;

    snprintf(phy_path, sizeof(phy_path), CONFIG_MAC80211_WIPHY_PATH"/%s/device/net", phy);
    if (!(d = opendir(phy_path)))
        return -1;

    for (p = readdir(d); p ; p = readdir(d)) {
        if (p->d_name &&
            strncmp(p->d_name, ".", 1) &&
            strstr(p->d_name, type)) {
            phy_name = strchomp(R(F(CONFIG_MAC80211_WIPHY_PATH"/%s/device/net/%s/phy80211/name",
                            phy, p->d_name)), "\r\n ");

            if (!strcmp(phy_name, phy)) {
                snprintf(buf + strlen(buf), len - strlen(buf), "%s ", p->d_name);
            }
        }
    }

    closedir(d);

    rtrimws(buf);

    if (!strlen(buf))
        return -1;

    LOGD("%s: list of all phy VIFs of type[%s]: %s", phy, type, buf);

    return 0;
}

/* Fetch any phy VIF of the type(ap/sta) specified */
static int
util_wifi_get_phy_any_vif_type(const char *phy,
                               char *buf,
                               int len,
                               char *type)
{
    struct dirent *p;
    char phy_path[BFR_SIZE_128];
    DIR *d;
    char *phy_name;

    memset(buf, 0, len);

    snprintf(phy_path, sizeof(phy_path), CONFIG_MAC80211_WIPHY_PATH"/%s/device/net", phy);
    if (!(d = opendir(phy_path)))
        return -1;

    for (p = readdir(d); p ; p = readdir(d)) {
        if (p->d_name && strncmp(p->d_name, ".", 1) &&
            strstr(p->d_name, type)) {
            phy_name = strchomp(R(F(CONFIG_MAC80211_WIPHY_PATH"/%s/device/net/%s/phy80211/name",
                            phy, p->d_name)), "\r\n ");

            if (!strcmp(phy_name, phy)) {
                strscpy(buf, p->d_name, len);
                break;
            }
        }
    }

    closedir(d);

    if (!strlen(buf))
        return -1;

    return 0;
}

static int
util_wifi_get_phy_all_vifs(const char *phy,
                       char *buf,
                       int len)
{
    struct dirent *p;
    char phy_path[BFR_SIZE_256];
    DIR *d;
    char *phy_name;

    memset(buf, 0, len);

    snprintf(phy_path, sizeof(phy_path), CONFIG_MAC80211_WIPHY_PATH"/%s/device/net", phy);
    if (!(d = opendir(phy_path)))
        return -1;

    for (p = readdir(d); p ; p = readdir(d)) {
        if (p->d_name && strncmp(p->d_name, ".", 1)) {
            phy_name = strchomp(R(F(CONFIG_MAC80211_WIPHY_PATH"/%s/device/net/%s/phy80211/name",
                            phy, p->d_name)), "\r\n ");

            if (!strcmp(phy_name, phy)) {
                snprintf(buf + strlen(buf), len - strlen(buf), "%s ", p->d_name);
            }
        }
    }

    closedir(d);
    return 0;
}

int util_get_vif_radio(const char *in_vif, char *phy_buf, int len)
{
    char sys_path[BFR_SIZE_128];

    snprintf(sys_path, sizeof(sys_path), "/sys/class/net/%s/phy80211/name", in_vif);
    if (util_file_read_str(sys_path, phy_buf, len) < 0)
        return -1;

    rtrimws(phy_buf);
    return 0;
}

static void
util_wifi_transform_macaddr(char *mac, int idx)
{
    if (idx == 0)
        return;

    mac[0] = ((((mac[0] >> 4) + 8 + idx - 2) & 0xf) << 4)
               | (mac[0] & 0xf)
               | 0x2;
}

static int
util_wifi_gen_macaddr(const char *phy,
                      char *macaddr,
                      int idx)
{
    int err;

    err = util_net_get_macaddr(phy, macaddr);
    if (err) {
        LOGW("%s: failed to get radio base macaddr: %d (%s)",
             phy, errno, strerror(errno));
        return err;
    }

    util_wifi_transform_macaddr(macaddr, idx);

    return 0;
}

static bool
util_wifi_get_macaddr_idx(const char *phy,
                          const char *vif,
                          int *idx)
{
    char vifmac[6];
    char mac[6];
    int err;
    int i;

    err = util_net_get_macaddr(vif, vifmac);
    if (err) {
        LOGW("%s: failed to get radio base macaddr: %d (%s)",
             phy, errno, strerror(errno));
        return err;
    }

    /* It's much more safer to brute-force search the answer
     * than trying to invert the transformation function
     * especially if it ends up with multiple indexing
     * strategies.
     */
    for (i = 0; i < 16; i++) {
        util_wifi_gen_macaddr(phy, mac, i);
        if (!memcmp(mac, vifmac, 6)) {
            *idx = i;
            return true;
        }
    }

    *idx = 0;
    return false;
}

static int
util_wifi_get_phy_vifs(const char *phy,
                       char *buf,
                       int len)
{
    struct dirent *p;
    char path[128];
    DIR *d;

    memset(buf, 0, len);
    snprintf(path, sizeof(path), CONFIG_MAC80211_WIPHY_PATH"/%s/device/net", phy);
    if (!(d = opendir(path)))
        return -1;

    for (p = readdir(d); p ; p = readdir(d)) {
        if (p->d_name && strncmp(p->d_name, ".", 1))
            snprintf(buf + strlen(buf), len - strlen(buf), "%s ", p->d_name);
    }

    closedir(d);
    return 0;
}

static int
util_wifi_any_phy_vif(const char *phy,
                      char *buf,
                      int len)
{
    char *p;
    if (util_wifi_get_phy_vifs(phy, buf, len) < 0)
        return -1;
    if (!(p = strtok(buf, " ")))
        return -1;
    return strlen(p) > 0 ? 0 : -1;
}

static bool
util_get_phy_chan(const char *phy,
                  int *chan)
{
    char ap_vif[BFR_SIZE_64] = "";

    if (util_wifi_get_phy_any_vif_type(phy, ap_vif, sizeof(ap_vif), IFNAME_TYPE_AP)) {
        LOGD("%s: get ap vif failed", phy);
        return false;
    }

    *chan = nl_req_get_iface_curr_chan(&target_nl_global, util_sys_ifname_to_idx(ap_vif));
    if (*chan > 0)
        return true;

    return false;
}

static bool
util_get_vif_chan(const char *vif,
                  int *chan)
{
    *chan = nl_req_get_iface_curr_chan(&target_nl_global, util_sys_ifname_to_idx(vif));

    if (*chan <= 0)
        return false;

    /* TODO: Handle CAC in progress case
     * This can happen when CSA is in progress of
         * completing and interfaces begin to change the
         * operational channel one-by-one.
         *
         * In that case the channel is undefined until after
         * CSA fully completes at which point all interfaces
         * are expected to report same channel.
         *
         * This assumes single-channel operation.
         * Multi-chann capable radios will likely require
         * ovsdb rework anyway.
         */

    return true;
}

static int
util_get_opmode(const char *vif, char *opmode, int len)
{
    if (vif && strlen(vif) == 0)
        return 0;

    if (nl_req_get_mode(&target_nl_global, vif, opmode, len) == true)
        return 1;

    LOGW("%s: failed to get opmode", vif);
    return 0;
}

static void
util_set_tx_power(const char *phy, const int tx_power_dbm)
{
    nl_req_set_txpwr(&target_nl_global, phy, tx_power_dbm);
    return;
}

static int
util_get_tx_power(const char *phy)
{
    char ap_vif[BFR_SIZE_64] = "";
    int txpwr = 0;

    if (util_wifi_get_phy_any_vif_type(phy, ap_vif, sizeof(ap_vif), IFNAME_TYPE_AP)) {
        LOGD("%s: get ap vif failed", phy);
        return 0;
    }

    txpwr = nl_req_get_txpwr(&target_nl_global, ap_vif);
    if (txpwr < 0)
        return 0;

    return txpwr;
}

/******************************************************************************
 * Target callback helpers
 *****************************************************************************/

static void
util_cb_vif_state_update(const char *vif)
{
    struct schema_Wifi_VIF_State vstate;
    const char *phy = NULL;
    char ifname[32];
    bool ok;
    char p_buf[32] = {0};

    LOGD("%s: updating state", vif);

    if (util_get_vif_radio(vif, p_buf, sizeof(p_buf)))
        LOGD("%s: failed to get vif radio", vif);
    else
        phy = strdupa(p_buf);

    STRSCPY(ifname, vif);

    ok = target_vif_state_get(ifname, &vstate);
    if (!ok) {
        LOGD("%s: failed to get vif state: %d (%s)",
             vif, errno, strerror(errno));
        return;
    }

    if (rops.op_vstate)
        rops.op_vstate(&vstate, phy);
}

static void
util_cb_vif_state_channel_sanity_update(const struct schema_Wifi_Radio_State *rstate)
{
    const struct kvstore *kv;
    char *vif;
    char vif_list[512];
    char *p = vif_list;

    if (rstate->channel_exists)
        if (!util_wifi_get_phy_all_vifs(rstate->if_name, p, sizeof(vif_list)))
            while ((vif = strsep(&p, " ")))
                if ((kv = util_kv_get(F("%s.last_channel", vif))))
                    if (atoi(kv->val) != rstate->channel) {
                        LOGI("%s: channel out of sync (%d != %d), forcing update",
                             vif, atoi(kv->val), rstate->channel);
                        util_cb_vif_state_update(vif);
                    }
}

static void
util_cb_phy_state_update(const char *phy)
{
    struct schema_Wifi_Radio_State rstate;
    char ifname[32];
    bool ok;

    LOGD("%s: updating state", phy);

    STRSCPY(ifname, phy);

    ok = target_radio_state_get(ifname, &rstate);
    if (!ok) {
        LOGW("%s: failed to get phy state: %d (%s)",
             phy, errno, strerror(errno));
        return;
    }

    if (rops.op_rstate)
        rops.op_rstate(&rstate);

    util_cb_vif_state_channel_sanity_update(&rstate);
}

/******************************************************************************
 * Target delayed callback helpers
 *****************************************************************************/

static void
util_cb_delayed_update_timer(struct ev_loop *loop,
                             ev_timer *timer,
                             int revents)
{
    const struct kvstore *kv;
    char *ifname;
    char *type;
    char *p;
    char *q;
    char *i;

    if (!(kv = util_kv_get(UTIL_CB_KV_KEY)))
        return;

    p = strdupa(kv->val);
    util_kv_set(UTIL_CB_KV_KEY, NULL);

    /* The ordering is intentional here. It
     * reduces the churn when vif states are
     * updated, e.g. due to channel change events
     * in which case updating phy will need to be
     * done once afterwards.
     */

    q = strdupa(p);
    while ((i = strsep(&q, " ")))
        if ((type = strsep(&i, ":")) && !strcmp(type, UTIL_CB_VIF) && (ifname = strsep(&i, "")))
            util_cb_vif_state_update(ifname);

    q = strdupa(p);
    while ((i = strsep(&q, " ")))
        if ((type = strsep(&i, ":")) && !strcmp(type, UTIL_CB_PHY) && (ifname = strsep(&i, "")))
                util_cb_phy_state_update(ifname);
}

static void
util_cb_delayed_update(const char *type, const char *ifname)
{
    const struct kvstore *kv;
    char buf[512];
    char *p;
    char *i;

    if ((kv = util_kv_get(UTIL_CB_KV_KEY))) {
        STRSCPY(buf, kv->val);
        p = strdupa(buf);
        while ((i = strsep(&p, " ")))
            if (!strcmp(i, F("%s:%s", type, ifname)))
                break;
        if (i) {
            LOGD("%s: delayed update already scheduled", ifname);
            return;
        }
    } else {
        ev_timer_init(&g_util_cb_timer, util_cb_delayed_update_timer, UTIL_CB_DELAY_SEC, 0);
        ev_timer_start(target_mainloop, &g_util_cb_timer);
    }

    LOGD("%s: scheduling delayed update '%s' += '%s:%s'",
         ifname, kv ? kv->val : "", type, ifname);
    STRSCAT(buf, " ");
    STRSCAT(buf, type);
    STRSCAT(buf, ":");
    STRSCAT(buf, ifname);
    util_kv_set(UTIL_CB_KV_KEY, buf);
}

/* FIXME: forward declarations are bad */
static void
hapd_sta_regen(struct hapd *hapd);

static void
util_cb_delayed_update_all(void)
{
    char phy[32];
    struct dirent *i;
    struct hapd *hapd;
    DIR *d;

    if (!(d = opendir("/sys/class/ieee80211")))
        goto vif_update;
    for (i = readdir(d); i; i = readdir(d)) {
        if (strstr(i->d_name, "phy")) {
            util_cb_delayed_update(UTIL_CB_PHY, i->d_name);
        }
    }
    closedir(d);

vif_update:
    if (!(d = opendir("/sys/class/net")))
        return;
    for (i = readdir(d); i; i = readdir(d)) {
        if (0 == util_wifi_get_parent(i->d_name, phy, sizeof(phy))) {
            hapd = hapd_lookup(i->d_name);
            if (hapd)
                hapd_sta_regen(hapd);
            util_cb_delayed_update(UTIL_CB_VIF, i->d_name);
        }
    }

    closedir(d);
}

/******************************************************************************
 * ctrl helpers
 *****************************************************************************/

static void
hapd_sta_report(struct hapd *hapd, const char *mac)
{
    struct schema_Wifi_Associated_Clients client;
    int exists;

    memset(&client, 0, sizeof(client));
    schema_Wifi_Associated_Clients_mark_all_present(&client);
    client._partial_update = true;
    exists = (hapd_sta_get(hapd, mac, &client) == 0);
    LOGI("%s: %s: updating exists=%d", hapd->ctrl.bss, mac, exists);

    if (rops.op_client)
        rops.op_client(&client, hapd->ctrl.bss, exists);
}

static void
hapd_sta_regen_iter(struct hapd *hapd, const char *mac, void *data)
{
    hapd_sta_report(hapd, mac);
}

static void
hapd_sta_regen(struct hapd *hapd)
{
    LOGI("%s: regenerating sta list", hapd->ctrl.bss);

    if (rops.op_flush_clients)
        rops.op_flush_clients(hapd->ctrl.bss);

    hapd_sta_iter(hapd, hapd_sta_regen_iter, NULL);
}

static void
wpas_report(struct wpas *wpas)
{
    struct schema_Wifi_VIF_State vstate;

    util_cb_delayed_update(UTIL_CB_VIF, wpas->ctrl.bss);
    util_cb_delayed_update(UTIL_CB_PHY, wpas->phy);

    /* scanfilter increases chance of finding bss entry in
     * scan results in congested rf env
     */
    memset(&vstate, 0, sizeof(vstate));
    wpas_bss_get(wpas, &vstate);
#if 0
    /*
     * The issue specific to "*scanfilter*" command is fixed in
     * the driver so this code is not required.
     */
    util_set_scanfilter(wpas->ctrl.bss, vstate.ssid);
#endif
}

/* ctrl -> target */

static void
hapd_sta_connected(struct hapd *hapd, const char *mac, const char *keyid)
{
    hapd_sta_report(hapd, mac);
}

static void
hapd_sta_disconnected(struct hapd *hapd, const char *mac)
{
    hapd_sta_report(hapd, mac);
}

static void
hapd_ap_enabled(struct hapd *hapd)
{
    util_cb_vif_state_update(hapd->ctrl.bss);
    util_cb_phy_state_update(hapd->phy);
    hapd_sta_regen(hapd);
}

static void
hapd_ap_disabled(struct hapd *hapd)
{
    util_cb_vif_state_update(hapd->ctrl.bss);
    util_cb_phy_state_update(hapd->phy);
    hapd_sta_regen(hapd);
}

static void
hapd_wps_active(struct hapd *hapd)
{
    util_cb_delayed_update(UTIL_CB_VIF, hapd->ctrl.bss);
}

static void
hapd_wps_success(struct hapd *hapd)
{
    util_cb_delayed_update(UTIL_CB_VIF, hapd->ctrl.bss);
}

static void
hapd_wps_timeout(struct hapd *hapd)
{
    util_cb_delayed_update(UTIL_CB_VIF, hapd->ctrl.bss);
}

static void
hapd_wps_disable(struct hapd *hapd)
{
    util_cb_delayed_update(UTIL_CB_VIF, hapd->ctrl.bss);
}

void set_hostapd_ctrl(const char *vif, const char *phy)
{
    int err = 0;
    const char *cmd;

    if (access(F("/var/run/wpa_supplicant-%s", phy), F_OK) < 0)
        return;

    cmd = F("timeout -s KILL 3 wpa_cli -p /var/run/wpa_supplicant-%s "
            "hostapd_ctrl /var/run/hostapd-%s/%s", phy, phy, vif);

    err = system(cmd);
    if (err)
        LOGD("%s: failed to run command[%s]", vif, cmd);
}

static void
wpas_connected(struct wpas *wpas, const char *bssid, int id, const char *id_str)
{
    char ap_vif[32] = {};

    wpas_report(wpas);

    if (util_wifi_get_phy_any_vif_type(wpas->phy, ap_vif, sizeof(ap_vif), IFNAME_TYPE_AP)) {
        LOGD("%s: get ap vif failed", wpas->phy);
        return;
    }

    set_hostapd_ctrl(ap_vif, wpas->phy);
}

static void
wpas_disconnected(struct wpas *wpas, const char *bssid, int reason, int local)
{
    wpas_report(wpas);
}

void dfs_update_chan_state(struct hapd *hapd, const int *chanlist, enum channel_state new_dfs_state)
{
    enum channel_state old_dfs_state = INVALID;

    while (*chanlist) {
        old_dfs_state = g_chan_status[*chanlist].state;

        /* Channel in NOP_STARTED state should be changed to NOP_FINISHED state first
         * before updating it to other DFS states.
         * Eg: Needed if we ever hit a scenario where radar event(NOP_STARTED) is received
         * first during CAC_STARTED period and then followed by a failed CAC_COMPLETED event.
         */
        if (g_chan_status[*chanlist].state == NOP_STARTED) {
            if (new_dfs_state == NOP_FINISHED)
                g_chan_status[*chanlist].state = new_dfs_state;
        } else {
            g_chan_status[*chanlist].state = new_dfs_state;
        }

        LOGW("%s: channel %d state updated %s -> %s",
            __func__, *chanlist,
            chan_state_to_str(old_dfs_state),
            chan_state_to_str(g_chan_status[*chanlist].state));

        chanlist++;
    }
    util_cb_vif_state_update(hapd->ctrl.bss);
    util_cb_phy_state_update(hapd->phy);
}

void dfs_update_chan_state_cac_started(struct hapd *hapd, char *bss_status)
{
    int chan = 0;
    int cf1 = 0;
    const int *chan_list = NULL;
    const char *k;
    const char *v;
    char *kv;

    while ((kv = strsep(&bss_status, "\r\n"))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "channel"))
                chan = atoi(v);
            else if (!strcmp(k, "vht_oper_centr_freq_seg0_idx"))
                cf1 = atoi(v);
        }
    }
    if (chan) {
        if (cf1)
            chan_list = dfs_get_chanlist_from_centerchan(chan, cf1);
        else
            chan_list = unii_5g_chan2list(chan, 20);
        if (chan_list)
            dfs_update_chan_state(hapd, chan_list, CAC_STARTED);
    }
}

int hostapd_status_get_interface_state(struct hapd *hapd)
{
    char sockdir[64] = "";
    char *bss_status;
    const char *k;
    const char *v;
    char *kv;

    snprintf(sockdir, sizeof(sockdir), "%s/hostapd-%s", HOSTAPD_CONTROL_PATH_DEFAULT, hapd->phy);

    bss_status = HOSTAPD_CLI(sockdir, hapd->ctrl.bss, "STATUS");
    if (!bss_status || (!strlen(bss_status)))
        return -1;

    while ((kv = strsep(&bss_status, "\r\n"))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if ((!strcmp(k, "state")) && (!strcmp(v, "DFS"))) {
                dfs_update_chan_state_cac_started(hapd, bss_status);
                return 0;
            }
        }
    }
    return 0;
}

static void
hapd_ctrl_opened(struct ctrl *ctrl)
{
    struct hapd *hapd = container_of(ctrl, struct hapd, ctrl);

    hapd_sta_regen(hapd);
    set_hostapd_ctrl(hapd->ctrl.bss, hapd->phy);

    if (hostapd_status_get_interface_state(hapd) < 0)
        LOGN("failed to get interface status");
}

static void
hapd_ctrl_closed(struct ctrl *ctrl)
{
    struct hapd *hapd = container_of(ctrl, struct hapd, ctrl);
    hapd_sta_regen(hapd);
    unlink(hapd->confpath);
    unlink(hapd->pskspath);
}

static void
wpas_ctrl_opened(struct ctrl *ctrl)
{
    char ap_vif[32] = {};
    struct wpas *wpas = container_of(ctrl, struct wpas, ctrl);
    wpas_report(wpas);

    if (util_wifi_get_phy_any_vif_type(wpas->phy, ap_vif, sizeof(ap_vif), IFNAME_TYPE_AP)) {
        LOGD("%s: AP vif not present", wpas->phy);
        return;
    }

    set_hostapd_ctrl(ap_vif, wpas->phy);
}

static void
wpas_ctrl_closed(struct ctrl *ctrl)
{
    struct wpas *wpas = container_of(ctrl, struct wpas, ctrl);
    wpas_report(wpas);
}

int radio_set_fallback_parents(char *phy)
{
    char sta_vif[32];
    const char *fallback_phy;
    int num = 0;
    struct fallback_parent parents[8];
    struct fallback_parent *parent;
    int err = 0;

    if (util_wifi_get_phy_any_vif_type(phy, sta_vif, sizeof(sta_vif), IFNAME_TYPE_STA)) {
        LOGD("%s: no sta vif found, skipping parent change", phy);
        return -1;
    }

    fallback_phy = wiphy_info_get_2ghz_ifname();
    if (!fallback_phy) {
        LOGD("%s: no phy found for 2.4G",phy);
        return -1;
    }

    if ((num = util_kv_get_fallback_parents(fallback_phy, parents, ARRAY_SIZE(parents))) <= 0) {
        LOGD("%s:no fallback parents configured", phy);
        return -1;
    }

    parent = &parents[0];
    err = runcmd("%s/parentchange.sh '%s' '%s' '%d'",
                 target_bin_dir(),
                 fallback_phy,
                 parent->bssid,
                 parent->channel);
    if (err) {
        LOGW("%s: failed to run parentchange.sh '%s' '%s' '%d': %d (%s)",
            __func__,
            fallback_phy,
            parent->bssid,
            parent->channel,
            errno,
            strerror(errno));
        return -1;
    }

    return 0;
}


int radio_check_valid_phy_channel(char *phy, int event_chan)
{
    char buffer[BFR_SIZE_4K] = "";
    char *line;
    int channel;
    char *buf = buffer;

    if (g_chan_status[event_chan].state == ALLOWED) {
        LOGN("%d channel state is allowed", event_chan);
        return -1;
    }

    /* checking radar detected channel is valid or not on phy interface */
    if (nl_req_get_channels(&target_nl_global, phy, buffer,sizeof(buffer)) < 0)
        LOGW("%s: failed to fetch channel information", __func__);

    while ((line = strsep(&buf, "\n")) != NULL) {
        if (sscanf(line, "chan %d", &channel) == 1) {
            if (channel == event_chan)
                return 1;
        }
    }

    LOGN("channel %d is invalid channel for %s interface", event_chan, phy);
    return -1;
}

static void hapd_dfs_event_cac_start(struct hapd *hapd, const char *event)
{
    char        *kv;
    const char  *k;
    const char  *v;
    int         chan = 0;
    int         cf1 = 0;
    const int   *chan_list = NULL;
    char        *parse_buf = strdupa(event);

    /*
     * Rely on centre channel seg0 to derive width as DFS_EVENT_CAC_START can send "width" with
     * enum chan_width values or vht_oper_chwidth conf values which do not map to the same bw.
     *
     * DFS-CAC-START freq=5260 chan=52 sec_chan=0, width=0, seg0=0, seg1=0, cac_time=60s
     * DFS-CAC-START freq=5260 chan=52 sec_chan=1, width=0, seg0=54, seg1=0, cac_time=60s
     * DFS-CAC-START freq=5580 chan=116 sec_chan=1, width=1, seg0=122, seg1=0, cac_time=60s
     */
    while ((kv = strsep(&parse_buf, " "))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "chan"))
                chan = atoi(v);
            else if (!strcmp(k, "seg0"))
                cf1 = atoi(v);
        }
    }
    if (chan) {
        if (radio_check_valid_phy_channel(hapd->phy, chan) < 0)
            return;

        LOGI("%s: event[DFS-CAC-START %s]", __func__, event);
        if (cf1)
            chan_list = dfs_get_chanlist_from_centerchan(chan, cf1);
        else
            chan_list = unii_5g_chan2list(chan, 20);
        if (chan_list)
            dfs_update_chan_state(hapd, chan_list, CAC_STARTED);
    }

    return;
}

static void hapd_dfs_event_cac_completed(struct hapd *hapd, const char *event)
{
    char        *kv;
    const char  *k;
    const char  *v;
    int         chan = 0;
    int         cf1 = 0;
    int         success = 0;
    const int   *chan_list = NULL;
    char        *parse_buf = strdupa(event);

    /*
     * DFS-CAC-COMPLETED success=0 freq=5580 ht_enabled=0 chan_offset=0 chan_width=3 cf1=5610 cf2=0
     * DFS-CAC-COMPLETED success=1 freq=5580 ht_enabled=0 chan_offset=0 chan_width=3 cf1=5610 cf2=0
     */
    while ((kv = strsep(&parse_buf, " "))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "freq"))
                chan = util_freq_to_chan(atoi(v));
            else if (!strcmp(k, "cf1"))
                cf1 = util_freq_to_chan(atoi(v));
            else if (!strcmp(k, "success"))
                success = atoi(v);
        }
    }
    if (chan) {
        if (radio_check_valid_phy_channel(hapd->phy, chan) < 0)
            return;

        LOGI("%s: event[DFS-CAC-COMPLETED %s]", __func__, event);
        if (cf1)
            chan_list = dfs_get_chanlist_from_centerchan(chan, cf1);
        if (chan_list) {
            if (success)
                dfs_update_chan_state(hapd, chan_list, CAC_COMPLETED);
            else
                dfs_update_chan_state(hapd, chan_list, NOP_FINISHED);
        }
    }

    return;
}

static void hapd_dfs_event_radar_detected(struct hapd *hapd, const char *event)
{
    char        *kv;
    const char  *k;
    const char  *v;
    int         chan = 0;
    int         cf1 = 0;
    const int   *chan_list = NULL;
    char        *parse_buf = strdupa(event);

    // DFS-RADAR-DETECTED freq=5580 ht_enabled=0 chan_offset=0 chan_width=3 cf1=5610 cf2=0
    while ((kv = strsep(&parse_buf, " "))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "freq"))
                chan = util_freq_to_chan(atoi(v));
            else if (!strcmp(k, "cf1"))
                cf1 = util_freq_to_chan(atoi(v));
        }
    }
    if (chan) {
        if (radio_check_valid_phy_channel(hapd->phy, chan) < 0)
            return;

        LOGI("%s: event[DFS-RADAR-DETECTED %s]", __func__, event);
        if (cf1)
            chan_list = dfs_get_chanlist_from_centerchan(chan, cf1);
        if (chan_list)
            dfs_update_chan_state(hapd, chan_list, NOP_STARTED);

        util_kv_radar_set(hapd->phy, chan);
    }

    if (radio_set_fallback_parents(hapd->phy) < 0) {
        LOGN("failed to set fallback parents");
        return;
    }
    return;
}

static void hapd_dfs_event_nop_finished(struct hapd *hapd, const char *event)
{
    char        *kv;
    const char  *k;
    const char  *v;
    int         chan = 0;
    int         cf1 = 0;
    const int   *chan_list = NULL;
    char        *parse_buf = strdupa(event);

    // DFS-NOP-FINISHED freq=5580 ht_enabled=0 chan_offset=0 chan_width=3 cf1=5610 cf2=0
    while ((kv = strsep(&parse_buf, " "))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "freq"))
                chan = util_freq_to_chan(atoi(v));
            else if (!strcmp(k, "cf1"))
                cf1 = util_freq_to_chan(atoi(v));
        }
    }
    if (chan) {
        if (radio_check_valid_phy_channel(hapd->phy, chan) < 0)
            return;

        LOGI("%s: event[DFS-NOP-FINISHED %s]", __func__, event);
        if (cf1)
            chan_list = dfs_get_chanlist_from_centerchan(chan, cf1);
        if (chan_list)
            dfs_update_chan_state(hapd, chan_list, NOP_FINISHED);
    }

    return;
}

static void hapd_dfs_event_pre_cac_expired(struct hapd *hapd, const char *event)
{
    char        *kv;
    const char  *k;
    const char  *v;
    int         chan = 0;
    int         cf1 = 0;
    const int   *chan_list = NULL;
    char        *parse_buf = strdupa(event);

    // DFS-PRE-CAC-EXPIRED freq=5580 ht_enabled=0 chan_offset=0 chan_width=3 cf1=5610 cf2=0
    while ((kv = strsep(&parse_buf, " "))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, "freq"))
                chan = util_freq_to_chan(atoi(v));
            else if (!strcmp(k, "cf1"))
                cf1 = util_freq_to_chan(atoi(v));
        }
    }
    if (chan) {
        if (radio_check_valid_phy_channel(hapd->phy, chan) < 0)
            return;

        LOGI("%s: event[DFS-PRE-CAC_EXPIRED %s]", __func__, event);
        if (cf1)
            chan_list = dfs_get_chanlist_from_centerchan(chan, cf1);
        if (chan_list)
            dfs_update_chan_state(hapd, chan_list, NOP_FINISHED);
    }

    return;
}

static void
hapd_ap_csa_finished(struct hapd *hapd, const char *event)
{
    // AP-CSA-FINISHED freq=5180 dfs=0
    LOGI("%s: event[AP-CSA-FINISHED %s]", __func__, event);

    util_cb_vif_state_update(hapd->ctrl.bss);
    util_cb_phy_state_update(hapd->phy);
}

static int
get_bhaul_sta_chan(const char *bss)
{
    int chan = 0;
    char sta_vif[32] = "";
    struct hapd *hapd = NULL;

    hapd = hapd_lookup(bss);
    if (!hapd)
        return 0;

    if (util_wifi_get_phy_any_vif_type(hapd->phy, sta_vif, sizeof(sta_vif), IFNAME_TYPE_STA))
        return 0;

    if (util_get_vif_chan(sta_vif, &chan)) {
        LOGI("%s:%s: override AP VIF with extender channel %d", hapd->phy, sta_vif, chan);
        return chan;
    }

    return 0;
}

static void
hostap_ctrl_discover(const char *bss)
{
    struct hapd *hapd = hapd_lookup(bss);
    struct wpas *wpas = wpas_lookup(bss);
    const char *phy;
    char mode[32] = {};
    char p_buf[32] = {0};

    if (util_get_vif_radio(bss, p_buf, sizeof(p_buf))) {
        LOGD("%s: failed to get bss radio", bss);
        return;
    }
    phy = strdupa(p_buf);

    if (util_wifi_is_ap_vlan(bss))
        return;

    if (phy)
        util_get_opmode(bss, mode, sizeof(mode));

    if (!strcmp(mode, "ap")) {
        if (wpas) ctrl_disable(&wpas->ctrl);
        if (!hapd) hapd = hapd_new(phy, bss);
        if (WARN_ON(!hapd)) return;
        STRSCPY_WARN(hapd->driver, "nl80211");
        hapd->ctrl.opened = hapd_ctrl_opened;
        hapd->ctrl.closed = hapd_ctrl_closed;
        hapd->ctrl.overrun = hapd_ctrl_opened;
        hapd->sta_connected = hapd_sta_connected;
        hapd->sta_disconnected = hapd_sta_disconnected;
        hapd->ap_enabled = hapd_ap_enabled;
        hapd->ap_disabled = hapd_ap_disabled;
        hapd->wps_active = hapd_wps_active;
        hapd->wps_success = hapd_wps_success;
        hapd->wps_timeout = hapd_wps_timeout;
        hapd->wps_disable = hapd_wps_disable;
        hapd->dfs_event_cac_start = hapd_dfs_event_cac_start;
        hapd->dfs_event_cac_completed = hapd_dfs_event_cac_completed;
        hapd->dfs_event_radar_detected = hapd_dfs_event_radar_detected;
        hapd->dfs_event_nop_finished = hapd_dfs_event_nop_finished;
        hapd->dfs_event_pre_cac_expired = hapd_dfs_event_pre_cac_expired;
        hapd->ap_csa_finished = hapd_ap_csa_finished;
        hapd->respect_multi_ap = 1;
        hapd->ieee80211n = 1;
        hapd->ieee80211ac = 1;
        hapd->ieee80211ax = 0;
        hapd->noscan = 1;
        hapd->ext_chan_override = get_bhaul_sta_chan(bss);
        util_radio_country_get(phy, hapd->country, sizeof(hapd->country));
        ctrl_enable(&hapd->ctrl);
        hapd = NULL;
    }

    if (!strcmp(mode, "sta")) {
        if (hapd) ctrl_disable(&hapd->ctrl);
        if (!wpas) wpas = wpas_new(phy, bss);
        if (WARN_ON(!wpas)) return;
        STRSCPY_WARN(wpas->driver, "nl80211");
        wpas->ctrl.opened = wpas_ctrl_opened;
        wpas->ctrl.closed = wpas_ctrl_closed;
        wpas->ctrl.overrun = wpas_ctrl_opened;
        wpas->connected = wpas_connected;
        wpas->disconnected = wpas_disconnected;
        wpas->respect_multi_ap = 1;
        ctrl_enable(&wpas->ctrl);
        wpas = NULL;
    }

    if (hapd) hapd_destroy(hapd);
    if (wpas) wpas_destroy(wpas);
}

static void
hostap_ctrl_destroy(const char *bss)
{
    struct hapd *hapd = hapd_lookup(bss);
    struct wpas *wpas = wpas_lookup(bss);

    if (hapd) hapd_destroy(hapd);
    if (wpas) wpas_destroy(wpas);
}

static void
hostap_ctrl_wps_session(const char *bss, int wps, int wps_pbc)
{
    struct hapd *hapd = hapd_lookup(bss);

    if (!hapd || !wps)
        return;

    if (WARN_ON(hapd_wps_cancel(hapd) != 0))
        return;

    if (!wps_pbc)
        return;

    if (WARN_ON(hapd_wps_activate(hapd) != 0))
        return;
}

static void
hostap_ctrl_apply(const char *bss,
               const struct schema_Wifi_VIF_Config *vconf,
               const struct schema_Wifi_Radio_Config *rconf,
               const struct schema_Wifi_Credential_Config *cconf,
               int num_cconf)
{
    struct hapd *hapd = hapd_lookup(bss);
    struct wpas *wpas = wpas_lookup(bss);
    bool first = false;
    int err = 0;

    WARN_ON(hapd && wpas);

    if (hapd) {
        first = (hapd->ctrl.wpa == NULL);
        err |= WARN_ON(hapd_conf_gen(hapd, rconf, vconf) < 0);
        err |= WARN_ON(hapd_conf_apply(hapd) < 0);
    }

    if (wpas) {
        first = (wpas->ctrl.wpa == NULL);
        err |= WARN_ON(wpas_conf_gen(wpas, rconf, vconf, cconf, num_cconf) < 0);
        err |= WARN_ON(wpas_conf_apply(wpas) < 0);
    }

    /* FIXME: This should be made generic and moved to WM.
     * It will need its semantics to be changed too.
     */
    if (!err && first)
        util_exec_scripts(bss);

    if (err)
        LOGI("%s: failed to apply config", bss);
}

void hapd_reload_ap_vif(const struct schema_Wifi_Radio_Config *rconf, const char *ap_vif)
{
    struct  hapd *hapd = NULL;
    struct  schema_Wifi_VIF_Config vconf;
    json_t  *where = NULL;
    int     err = 0;

    LOGE("%s: VIF down", ap_vif);

    if (!(where = ovsdb_where_simple(SCHEMA_COLUMN(Wifi_VIF_Config, if_name), ap_vif)))
        return;

    if (!ovsdb_table_select_one_where(&table_Wifi_VIF_Config, where, &vconf))
        return;

    LOGW("%s: reloading VIF", ap_vif);

    hapd = hapd_lookup(ap_vif);
    if (hapd) {
        unlink(hapd->confpath);
        unlink(hapd->pskspath);
        hapd_destroy(hapd);
    }

    hostap_ctrl_discover(ap_vif);
    hapd = hapd_lookup(ap_vif);

    if (hapd) {
        err |= WARN_ON(hapd_conf_gen(hapd, rconf, &vconf) < 0);
        err |= WARN_ON(hapd_conf_apply(hapd) < 0);
    }

    if (err)
        LOGD("%s: failed to apply config", ap_vif);
}

/******************************************************************************/

static int util_hostapd_acl_update(const char *phy, const char *vif, const char *mac_list_type, char *mac_list_buf)
{
    if (strstr(vif, "sta"))
        return false;

    if (!strcmp(mac_list_type, "whitelist"))
        return hostapd_mac_acl_accept_add(phy, vif, mac_list_buf);
    else if (!strcmp(mac_list_type, "blacklist"))
        return hostapd_mac_acl_deny_add(phy, vif, mac_list_buf);
    else
        return hostapd_mac_acl_clear(phy, vif);
}

static bool util_hostapd_get_hw_mode(const char *phy, char *buf, int buf_len)
{
    char ap_vif[32] = {};

    if (util_wifi_get_phy_any_vif_type(phy, ap_vif, sizeof(ap_vif), IFNAME_TYPE_AP)) {
        LOGD("%s: get ap vif failed", phy);
        return false;
    }

    return hostapd_status_get_hw_mode(phy, ap_vif, buf, buf_len);
}

static bool util_get_bcn_int(const char *phy, int *val)
{
    char ap_vif[BFR_SIZE_64] = "";

    if (util_wifi_get_phy_any_vif_type(phy, ap_vif, sizeof(ap_vif), IFNAME_TYPE_AP)) {
        LOGD("%s: get ap vif failed", phy);
        return false;
    }

    return hostapd_status_get_bcn_int(phy, ap_vif, val);
}

/******************************************************************************
 * BM and BSAL
 *****************************************************************************/

int
target_bsal_init(bsal_event_cb_t event_cb, struct ev_loop *loop)
{
    return nl_bsal_init(event_cb, loop);
}

int
target_bsal_cleanup(void)
{
    return nl_bsal_cleanup();
}

int
target_bsal_iface_add(const bsal_ifconfig_t *ifcfg)
{
    return nl_bsal_iface_add(ifcfg);
}

int
target_bsal_iface_update(const bsal_ifconfig_t *ifcfg)
{
    return nl_bsal_iface_update(ifcfg);
}

int
target_bsal_iface_remove(const bsal_ifconfig_t *ifcfg)
{
    return nl_bsal_iface_remove(ifcfg);
}

int
target_bsal_client_add(const char *ifname,
                       const uint8_t *mac_addr,
                       const bsal_client_config_t *conf)
{
    return nl_bsal_client_add(ifname, mac_addr, conf);
}

int
target_bsal_client_update(const char *ifname,
                          const uint8_t *mac_addr,
                          const bsal_client_config_t *conf)
{
    return nl_bsal_client_update(ifname, mac_addr, conf);
}

int
target_bsal_client_remove(const char *ifname,
                          const uint8_t *mac_addr)
{
    return nl_bsal_client_remove(ifname, mac_addr);
}

int
target_bsal_client_measure(const char *ifname,
                           const uint8_t *mac_addr, int num_samples)
{
    return nl_bsal_client_measure(ifname, mac_addr, num_samples);
}

int
target_bsal_client_info(const char *ifname,
                        const uint8_t *mac_addr,
                        bsal_client_info_t *info)
{
    return nl_bsal_client_info(ifname, mac_addr, info);
}

int
target_bsal_client_disconnect(const char *ifname, const uint8_t *mac_addr,
                              bsal_disc_type_t type, uint8_t reason)
{
    return nl_bsal_client_disconnect(ifname, mac_addr, type, reason);
}

int
target_bsal_bss_tm_request(const char *ifname,
                           const uint8_t *mac_addr, const bsal_btm_params_t *btm_params)
{
    return nl_bsal_bss_tm_request(ifname, mac_addr, btm_params);
}

int
target_bsal_rrm_beacon_report_request(const char *ifname,
                                      const uint8_t *mac_addr,
                                      const bsal_rrm_params_t *rrm_params)
{
    return nl_bsal_rrm_beacon_report_request(ifname, mac_addr, rrm_params);
}

int target_bsal_rrm_set_neighbor(const char *ifname, const bsal_neigh_info_t *nr)
{
    return nl_bsal_rrm_set_neighbor(ifname, nr);
}

int target_bsal_rrm_remove_neighbor(const char *ifname, const bsal_neigh_info_t *nr)
{
    return nl_bsal_rrm_remove_neighbor(ifname, nr);
}

int target_bsal_send_action(const char *ifname, const uint8_t *mac_addr,
                         const uint8_t *data, unsigned int data_len)
{
    return nl_bsal_send_action(ifname, mac_addr, data, data_len);
}

/******************************************************************************
 * DPP Support
 *****************************************************************************/

bool target_dpp_supported(void)
{
    return kconfig_enabled(CONFIG_TARGET_USE_DPP);
}

bool target_dpp_config_set(const struct schema_DPP_Config **config)
{
    return ctrl_dpp_config(config);
}

/******************************************************************************
 * Netlink event handling
 *****************************************************************************/

#define util_nl_each_msg(buf, hdr, len) \
    for (hdr = buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len))

#define util_nl_each_msg_type(buf, hdr, len, type) \
    util_nl_each_msg(buf, hdr, len) \
        if (hdr->nlmsg_type == type)

#define util_nl_each_attr(hdr, attr, attrlen) \
    for (attr = NLMSG_DATA(hdr) + NLMSG_ALIGN(sizeof(struct ifinfomsg)), \
         attrlen = NLMSG_PAYLOAD(hdr, sizeof(struct ifinfomsg)); \
         RTA_OK(attr, attrlen); \
         attr = RTA_NEXT(attr, attrlen))

#define util_nl_each_attr_type(hdr, attr, attrlen, type) \
    util_nl_each_attr(hdr, attr, attrlen) \
        if (attr->rta_type == type)

static void
util_nl_listen_stop(void)
{
    ev_io_stop(target_mainloop, &util_nl_io);
    close(util_nl_fd);
    util_nl_fd = -1;
}

static void
util_nl_parse(const void *buf, unsigned int len)
{
    const struct nlmsghdr *hdr;
    const struct rtattr *attr;
    struct ifinfomsg *ifm;
    char ifname[32];
    int attrlen;
    bool created;
    bool deleted;

    util_nl_each_msg(buf, hdr, len)
        if (hdr->nlmsg_type == RTM_NEWLINK ||
            hdr->nlmsg_type == RTM_DELLINK) {

            memset(ifname, 0, sizeof(ifname));

            util_nl_each_attr_type(hdr, attr, attrlen, IFLA_IFNAME)
                memcpy(ifname, RTA_DATA(attr), RTA_PAYLOAD(attr));

            if (strlen(ifname) == 0)
                continue;

            hostap_ctrl_discover(ifname);

            ifm = NLMSG_DATA(hdr);
            created = (hdr->nlmsg_type == RTM_NEWLINK) && (ifm->ifi_change == ~0U);
            deleted = (hdr->nlmsg_type == RTM_DELLINK);
            if ((created || deleted) &&
                (access(F("/sys/class/net/%s", ifname), R_OK) == 0))
                util_cb_delayed_update(UTIL_CB_VIF, ifname);
            if (deleted && util_wifi_is_ap_vlan(ifname))
                util_cb_delayed_update(UTIL_CB_VIF, ifname);
        }
}

static int util_nl_listen_start(void);

static void
util_nl_listen_cb(struct ev_loop *loop,
                  ev_io *watcher,
                  int revents)
{
    char buf[32768];
    int len;

    len = recvfrom(util_nl_fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, 0);
    if (len < 0) {
        if (errno == EAGAIN)
            return;

        if (errno == ENOBUFS) {
            LOGW("netlink overrun, lost some events, forcing update");
            util_cb_delayed_update_all();
            return;
        }

        LOGW("failed to recvfrom(): %d (%s), restarting listening for netlink",
             errno, strerror(errno));
        util_nl_listen_stop();
        util_nl_listen_start();
        return;
    }

    LOGT("%s: received %d bytes", __func__, len);

    util_nl_parse(buf, len);
}

static int
util_nl_listen_start(void)
{
    struct sockaddr_nl addr;
    int err;
    int fd;
    int v;

    if (util_nl_fd != -1)
        return 0;

    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        LOGW("%s: failed to create socket: %d (%s)",
             __func__, errno, strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGW("%s: failed to bind: %d (%s)",
             __func__, errno, strerror(errno));
        close(fd);
        return -1;
    }

    /* In some cases it may take dozen of seconds for the
     * main loop to reach netlink listening callback. By the
     * time there may have been a lot of messages queued.
     *
     * Without a big enough buffer to absorb bursts, e.g.
     * during interface (re)configuration, it was possible
     * to drop some netlink events. While it should always
     * be considered possible it's good to reduce the
     * likeliness of that.
     */
    v = 2 * 1024 * 1024;
    err = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v));
    if (err) {
        LOGW("%s: failed to set so_rcvbuf = %d: %d (%s), continuing",
             __func__, v, errno, strerror(errno));
    }

    util_nl_fd = fd;
    ev_io_init(&util_nl_io, util_nl_listen_cb, fd, EV_READ);
    ev_io_start(target_mainloop, &util_nl_io);

    return 0;
}

/******************************************************************************
 * Radio utilities
 *****************************************************************************/

static const char *
util_radio_channel_state(const char *line, int channel)
{
   /* key = channel number, value = { "state": "allowed" }
    * channel states:
    *     "allowed" - no dfs/always available
    *     "nop_finished" - dfs/CAC required before beaconing
    *     "nop_started" - dfs/channel disabled, don't start CAC
    *     "cac_started" - dfs/CAC started
    *     "cac_completed" - dfs/pass CAC beaconing
    */

    if (!strstr(line, " DFS"))
        return"{\"state\":\"allowed\"}";

    /*
     * DFS_NOP_FINISHED can indicate CAC_STARTED or NOP_FINISHED state
     * DFS_CAC_COMPLETED indicates CAC_COMPLETED state
     * DFS_NOP_STARTED indicates NOP_STARTED state (radar detected)
     */
    if (strstr(line, " DFS_NOP_FINISHED")) {
        if (g_chan_status[channel].state == CAC_STARTED)
            return "{\"state\": \"cac_started\"}";
        if (g_chan_status[channel].state != NOP_FINISHED)
            LOGE("%s: DFS channel[%d] state[%d] is out of sync with driver state[DFS_NOP_FINISHED]!",
                __func__, channel, g_chan_status[channel].state);
        return "{\"state\": \"nop_finished\"}";
    }
    if (strstr(line, " DFS_NOP_STARTED")) {
        if (g_chan_status[channel].state != NOP_STARTED)
            LOGE("%s: DFS channel[%d] state[%d] is out of sync with driver state[DFS_NOP_STARTED]!",
                __func__, channel, g_chan_status[channel].state);
        return "{\"state\": \"nop_started\"}";
    }
    if (strstr(line, " DFS_CAC_COMPLETED")) {
        if (g_chan_status[channel].state != CAC_COMPLETED)
            LOGE("%s: DFS channel[%d] state[%d] is out of sync with driver state[DFS_CAC_COMPLETED]!",
                __func__, channel, g_chan_status[channel].state);
        return "{\"state\": \"cac_completed\"}";
    }

    return "{\"state\": \"nop_started\"}";
}

static void
util_radio_channel_list_get(const char *phy, struct schema_Wifi_Radio_State *rstate)
{
    char    *line;
    int     channel;
    char    buffer[BFR_SIZE_4K] = "";
    char    *buf = buffer;

    if (nl_req_get_channels(&target_nl_global, phy, buffer, sizeof(buffer)) < 0)
        LOGW("%s: failed to fetch channel information", __func__);

    while ((line = strsep(&buf, "\n")) != NULL) {
        LOGD("%s line: |%s|", phy, line);
        if (sscanf(line, "chan %d", &channel) == 1) {
            rstate->allowed_channels[rstate->allowed_channels_len++] = channel;
            SCHEMA_KEY_VAL_APPEND(rstate->channels, F("%d", channel), util_radio_channel_state(line, channel));
        }
    }
}

static void
util_radio_fallback_parents_get(const char *phy, struct schema_Wifi_Radio_State *rstate)
{
    struct fallback_parent parents[8];
    int parents_num;
    int i;

    parents_num = util_kv_get_fallback_parents(phy, &parents[0], ARRAY_SIZE(parents));

    for (i = 0; i < parents_num; i++)
        SCHEMA_KEY_VAL_APPEND_INT(rstate->fallback_parents, parents[i].bssid, parents[i].channel);
}

static void
util_radio_fallback_parents_set(const char *phy, const struct schema_Wifi_Radio_Config *rconf)
{
    char buf[512] = {};
    int i;

    for (i = 0; i < rconf->fallback_parents_len; i++) {
        LOGI("%s: fallback_parents[%d] %s %d", phy, i,
             rconf->fallback_parents_keys[i],
             rconf->fallback_parents[i]);
        strscat(buf, F("%d %s,", rconf->fallback_parents[i], rconf->fallback_parents_keys[i]), sizeof(buf));
    }

    util_kv_set(F("%s.fallback_parents", phy), strlen(buf) ? buf : NULL);
}

static bool
util_vif_ht_mode_get(const char *vif, char *htmode, int htmode_len)
{
    return nl_req_get_ht_mode(&target_nl_global, vif, htmode, htmode_len);
}

static bool
util_radio_ht_mode_get(const char *phy, char *htmode, int htmode_len)
{
    char ap_vif[BFR_SIZE_64] = "";

    if (util_wifi_get_phy_any_vif_type(phy, ap_vif, sizeof(ap_vif), IFNAME_TYPE_AP)) {
        LOGD("%s: get ap vif failed", phy);
        return false;
    }

    return nl_req_get_ht_mode(&target_nl_global, ap_vif, htmode, htmode_len);
}

static bool
util_radio_country_get(const char *phy, char *country, int country_len)
{
    char buf[32];
    int err;

    memset(country, '\0', country_len);
    if ((err = nl_req_get_reg_dom(&target_nl_global, buf)) < 0) {
        LOGW("%s: failed to get country: %d", phy, err);
        return false;
    }

    strscpy(country, buf, country_len);

    return strlen(country);
}

/******************************************************************************
 * Radio implementation
 *****************************************************************************/

bool target_radio_state_get(char *phy, struct schema_Wifi_Radio_State *rstate)
{
    const struct wiphy_info *wiphy_info;
    const char *freq_band;
    const char *hw_type;
    char buf[512];
    char *vif;
    int v;
    char htmode[32];
    char country[32];
    char hwmode[32];

    memset(htmode, '\0', sizeof(htmode));
    memset(rstate, 0, sizeof(*rstate));

    schema_Wifi_Radio_State_mark_all_present(rstate);
    rstate->_partial_update = true;
    rstate->vif_states_present = false;
    rstate->radio_config_present = false;
    rstate->channel_sync_present = false;
    rstate->channel_mode_present = false;

    wiphy_info = wiphy_info_get(phy);
    if (!wiphy_info) {
        LOGW("%s: failed to identify radio", phy);
        return false;
    }

    hw_type = wiphy_info->chip;
    freq_band = wiphy_info->band;

    if (util_wifi_any_phy_vif(phy, vif = A(32))) {
        LOGD("%s: no vifs, some rstate bits will be missing", phy);
    }

    if ((rstate->mac_exists = (0 == util_net_get_phy_macaddr_str(phy, buf, sizeof(buf)))))
        STRSCPY(rstate->mac, buf);

    if ((rstate->enabled_exists = util_net_phy_exists(phy, &v)))
        rstate->enabled = v;

    if ((rstate->channel_exists = util_get_phy_chan(phy, &v)))
        rstate->channel = v;

    if ((rstate->bcn_int_exists = util_get_bcn_int(phy, &v)))
        rstate->bcn_int = v;

    if ((rstate->ht_mode_exists = util_radio_ht_mode_get(phy, htmode, sizeof(htmode))))
        STRSCPY(rstate->ht_mode, htmode);

    if ((rstate->country_exists = util_radio_country_get(phy, country, sizeof(country))))
        STRSCPY(rstate->country, country);

    STRSCPY(rstate->if_name, phy);
    STRSCPY(rstate->hw_type, hw_type);
    STRSCPY(rstate->freq_band, freq_band);

    rstate->if_name_exists = true;
    rstate->hw_type_exists = true;
    rstate->enabled_exists = true;
    rstate->freq_band_exists = true;
    rstate->hw_params_len = 0;

    if ((rstate->hw_mode_exists = util_hostapd_get_hw_mode(phy, hwmode, sizeof(hwmode))))
        STRSCPY(rstate->hw_mode, hwmode);

    if ((rstate->tx_power = util_get_tx_power(phy)) > 0)
        rstate->tx_power_exists = true;

    util_radio_channel_list_get(phy, rstate);
    util_radio_fallback_parents_get(phy, rstate);
    util_kv_radar_get(phy, rstate);

    return true;
}

int util_channel_switch(const struct schema_Wifi_Radio_Config *rconf, const char *phy)
{
    int     width = 0;
    char    mode[BFR_SIZE_32] = "";
    char    opt_chan_info[BFR_SIZE_64] = "";
    int     sec_chan_offset = 0;
    char    sec_chan_offset_str[BFR_SIZE_64] = "";
    int     center_chan = 0;
    int     center_freq1 = 0;
    char    center_freq1_str[BFR_SIZE_64] = "";
    int     ap_vif_curr_chan = 0;
    char    ap_vif_curr_htmode[BFR_SIZE_32] = "";
    char    ap_vif_list[BFR_SIZE_128] = "";
    char    sta_vif_list[BFR_SIZE_128] = "";
    char    *p_ap_vif_list = ap_vif_list;
    char    vif[BFR_SIZE_32] = "";
    bool    update_channel = false;
    const char *ap_vif = NULL;

    if (util_wifi_get_all_phy_vif_type(phy, ap_vif_list, sizeof(ap_vif_list), IFNAME_TYPE_AP) < 0) {
        LOGI("%s: no ap vaps, channel %d will be set on first vap if possible", phy, rconf->channel);
        return -1;
    }

    while ((ap_vif = strsep(&p_ap_vif_list, " "))) {
        if (util_get_vif_chan(ap_vif, &ap_vif_curr_chan)
            && util_vif_ht_mode_get(ap_vif, ap_vif_curr_htmode, sizeof(ap_vif_curr_htmode))) {
            if ((rconf->channel == ap_vif_curr_chan) && (!strcmp(rconf->ht_mode, ap_vif_curr_htmode)))
                LOGN("%s: already in newly requested channel and htmode", __func__);
            else {
                if ((!util_wifi_get_all_phy_vif_type(phy, sta_vif_list, sizeof(sta_vif_list), IFNAME_TYPE_STA)) &&
                    (rconf->channel == ap_vif_curr_chan) &&
                    (strcmp(rconf->ht_mode, ap_vif_curr_htmode) != 0))
                    LOGN("%s: htmode reconfig not supported when bhaul-sta is connected on same radio", __func__);
                else {
                    update_channel = true;
                    strscpy(vif, ap_vif, strlen(ap_vif) + 1);
                    LOGN("%s: update channel:%d -> %d, htmode:%s -> %s", ap_vif, ap_vif_curr_chan, rconf->channel,
                        ap_vif_curr_htmode, rconf->ht_mode);
                }
            }
        } else if (ap_vif_curr_chan == 0)
            hapd_reload_ap_vif(rconf, ap_vif);
    }

    if (!update_channel)
        return 0;

    sec_chan_offset = get_sec_chan_offset(rconf);
    if (sec_chan_offset != -EINVAL)
        snprintf(sec_chan_offset_str, sizeof(sec_chan_offset_str), "sec_channel_offset=%d", sec_chan_offset);

    ht_mode_to_mode(rconf, mode, sizeof(mode));

    if (!ht_mode_to_bw(rconf, &width))
        snprintf(opt_chan_info, sizeof(opt_chan_info), "bandwidth=%d %s", width, mode);

    if ((width > 20) || (strstr(mode, "vht"))) {
        if ((center_chan = unii_5g_centerfreq(rconf->ht_mode, rconf->channel)) > 0) {
            center_freq1 = util_chan_to_freq(center_chan);
            if (center_freq1)
                snprintf(center_freq1_str, sizeof(center_freq1_str), "center_freq1=%d", center_freq1);
        }
    }

    return hostapd_chan_switch(phy, vif, rconf->channel, center_freq1_str, sec_chan_offset_str, opt_chan_info);
}

bool
target_radio_config_set2(const struct schema_Wifi_Radio_Config *rconf,
                         const struct schema_Wifi_Radio_Config_flags *changed)
{
    const char *phy = rconf->if_name;

    if ((changed->channel || changed->ht_mode)) {
        if (rconf->channel_exists && rconf->channel > 0 && rconf->ht_mode_exists)
            if (util_channel_switch(rconf, phy) < 0)
                LOGN("%s: error received while trying to set new channel/ht_mode", __func__);
    }

    if (changed->fallback_parents)
        util_radio_fallback_parents_set(phy, rconf);

    if (changed->tx_power)
        util_set_tx_power(phy, rconf->tx_power);

    util_cb_phy_state_update(phy);
report:
    util_cb_delayed_update(UTIL_CB_PHY, phy);

    return true;
}

/******************************************************************************
 * Vif utilities
 *****************************************************************************/

static char *
util_vif_get_vconf_maclist(const struct schema_Wifi_VIF_Config *vconf,
                           char *buf,
                           size_t len)
{
    int i;
    memset(buf, 0, len);
    for (i = 0; i < vconf->mac_list_len; i++) {
        strlcat(buf, vconf->mac_list[i], len);
        strlcat(buf, " ", len);
    }
    if (strlen(buf) == len - 1)
        LOGW("%s: mac list truncated", vconf->if_name);
    return buf;
}

/******************************************************************************
 * Vif implementation
 *****************************************************************************/

bool
target_vif_config_set2(const struct schema_Wifi_VIF_Config *vconf,
                       const struct schema_Wifi_Radio_Config *rconf,
                       const struct schema_Wifi_Credential_Config *cconfs,
                       const struct schema_Wifi_VIF_Config_flags *changed,
                       int num_cconfs)
{
    const char *phy = rconf->if_name;
    const char *vif = vconf->if_name;
    char macaddr[6];

    if (!rconf ||
        changed->enabled ||
        changed->mode ||
        changed->vif_radio_idx) {
        hostap_ctrl_destroy(vif);

        if (access(F("/sys/class/net/%s", vif), X_OK) == 0) {
            LOGI("%s: deleting netdev", vif);
            /* Sync the DFS channel states with the driver
             * If a channel is in cac_started state and the interface is deleted, then we will not get
             * further events like DFS-CAC-COMPLETED from hostapd for this channel and the channel will
             * always remain in cac_started state.
             */
            nl_req_init_channels(&target_nl_global, vif, g_chan_status);
            nl_req_del_iface(&target_nl_global, vif);
        }

        if (!rconf || !vconf->enabled)
            goto done;

        if (util_wifi_gen_macaddr(phy, macaddr, vconf->vif_radio_idx)) {
            LOGW("%s: failed to generate mac address: %d (%s)", vif, errno, strerror(errno));
            return false;
        }

        LOGI("vif value=:%s\n",vif);
        LOGI("%s: creating netdev with mac %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx on channel %d",
             vif,
             macaddr[0], macaddr[1], macaddr[2],
             macaddr[3], macaddr[4], macaddr[5],
             rconf->channel_exists ? rconf->channel : 0);

        nl_req_add_iface(&target_nl_global, vif, phy, vconf->mode, macaddr);

        hostap_ctrl_discover(vif);
    }

    if (rconf->tx_power_exists)
        util_set_tx_power(phy, rconf->tx_power);

    if ((changed->mac_list_type) || (changed->mac_list)) {
        if (vconf->mac_list_type_exists)
            if (!util_hostapd_acl_update(phy, vif,
                                        vconf->mac_list_type,
                                        util_vif_get_vconf_maclist(vconf, A(4096))))
                LOGT("%s: failed to update mac acl configurations", __func__);
    }

    hostap_ctrl_apply(vif, vconf, rconf, cconfs, num_cconfs);
    if (changed->wps_pbc || changed->wps || changed->wps_pbc_key_id) {
        hostap_ctrl_wps_session(vif, vconf->wps, vconf->wps_pbc);
        util_ovsdb_wpa_clear(vconf->if_name);
    }
done:
    util_cb_vif_state_update(vif);
    util_cb_delayed_update(UTIL_CB_PHY, phy);

    LOGI("%s: (re)config complete", vif);
    return true;
}

bool target_vif_state_get(char *vif, struct schema_Wifi_VIF_State *vstate)
{
    struct hapd *hapd = hapd_lookup(vif);
    struct wpas *wpas = wpas_lookup(vif);
    char phy[32];
    char buf[256];
    int err;
    int v;

    memset(vstate, 0, sizeof(*vstate));

    schema_Wifi_VIF_State_mark_all_present(vstate);
    vstate->_partial_update = true;
    vstate->associated_clients_present = false;
    vstate->vif_config_present = false;

    STRSCPY(vstate->if_name, vif);
    vstate->if_name_exists = true;

    if ((vstate->enabled_exists = util_net_ifname_exists(vif, &v)))
        vstate->enabled = !!v;

    util_kv_set(F("%s.last_channel", vif), NULL);

    if (vstate->enabled_exists && !vstate->enabled)
        return true;

    err = util_wifi_get_parent(vif, phy, sizeof(phy));
    if (err) {
        LOGE("%s: failed to read parent phy ifname: %d (%s)",
             vif, errno, strerror(errno));
        return false;
    }

    if ((vstate->mode_exists = util_get_opmode(vif, buf, sizeof(buf))))
        STRSCPY(vstate->mode, buf);

    if (util_wifi_is_ap_vlan(vif))
        SCHEMA_SET_STR(vstate->mode, "ap_vlan");

    vstate->mac_list_type_exists = hostapd_get_mac_acl_info(phy, vif, vstate);

    if ((vstate->mac_exists = (0 == util_net_get_macaddr_str(vif, buf, sizeof(buf)))))
        STRSCPY(vstate->mac, buf);

    if ((vstate->channel_exists = util_get_vif_chan(vif, &v)))
        vstate->channel = v;

    util_kv_set(F("%s.last_channel", vif),
                vstate->channel_exists ? F("%d", vstate->channel) : "");

    if ((vstate->vif_radio_idx_exists = util_wifi_get_macaddr_idx(phy, vif, &v)))
        vstate->vif_radio_idx = v;

    if (strstr(vstate->if_name, HOME_AP_24)) {
        vstate->min_hw_mode_exists = true;
        STRSCPY(vstate->min_hw_mode, "11b");
    }
    if (strstr(vstate->if_name, BHAUL_AP_24) || strstr(vstate->if_name, ONBOARD_AP_24)) {
        vstate->min_hw_mode_exists = true;
        STRSCPY(vstate->min_hw_mode, "11g");
    }
    if (strstr(vstate->if_name, HOME_AP_PREFIX)) {
        vstate->ap_bridge_exists = true;
        vstate->ap_bridge = 0;
    }

    if (hapd) hapd_bss_get(hapd, vstate);
    if (wpas) wpas_bss_get(wpas, vstate);

    return true;
}

/******************************************************************************
 * Radio config init
 *****************************************************************************/

static void
target_radio_config_init_check_runtime(void)
{
    assert(0 == util_exec_simple("which", "hostapd"));
    assert(0 == util_exec_simple("which", "hostapd_cli"));
    assert(0 == util_exec_simple("which", "wpa_supplicant"));
    assert(0 == util_exec_simple("which", "wpa_cli"));
    assert(0 == util_exec_simple("which", "grep"));
    assert(0 == util_exec_simple("which", "awk"));
    assert(0 == util_exec_simple("which", "cut"));
    assert(0 == util_exec_simple("which", "xargs"));
    assert(0 == util_exec_simple("which", "readlink"));
    assert(0 == util_exec_simple("which", "basename"));
    assert(0 == util_exec_simple("which", "iw"));
}

static void
target_radio_init_discover(EV_P_ ev_async *async, int events)
{
    DIR *d;
    struct dirent *p;

    if (!(d = opendir(CONFIG_MAC80211_WIPHY_PATH)))
        goto vif_update;

    LOGI("enumerating interfaces");
    for (p = readdir(d); p ; p = readdir(d)) {
        if (strstr(p->d_name, CONFIG_MAC80211_WIPHY_PREFIX))
            util_cb_delayed_update(UTIL_CB_PHY, p->d_name);
    }
    closedir(d);

vif_update:
    if (!(d = opendir("/sys/class/net")))
        return;

    for (p = readdir(d); p ; p = readdir(d)) {
        // Check whether wifi vif interfaces are already present
        if (access(F("/sys/class/net/%s/phy80211/name", p->d_name), F_OK) == 0)
            util_cb_delayed_update(UTIL_CB_VIF, p->d_name);
    }

    closedir(d);

    ev_async_stop(EV_DEFAULT, async);
}

void wm_del_unused_iface()
{
    runcmd("%s/wm_del_unused_iface.sh", target_bin_dir());
}

bool
target_radio_init(const struct target_radio_ops *ops)
{
    static ev_async async;

    rops = *ops;

    target_radio_config_init_check_runtime();

    wm_del_unused_iface();

    if (netlink_wm_init(&target_nl_global)) {
        LOGE("%s: failed to initialize netlink info", __func__);
        return false;
    }

    if (wiphy_info_init(&target_nl_global)) {
        LOGE("%s: failed to initialize wiphy info", __func__);
        return false;
    }

    if (util_nl_listen_start()) {
        LOGE("%s: failed to start netlink listener", __func__);
        return false;
    }
    /* Workaround: due to target_radio_init()
     * being called before Wifi_Associated_Clients
     * is cleaned up, discovery must be deferred
     * until later so clients can actually be
     * picked up.
     */
    ev_async_init(&async, target_radio_init_discover);
    ev_async_start(EV_DEFAULT, &async);
    ev_async_send(EV_DEFAULT, &async);

    /* See target_radio_config_init2() for details */
    OVSDB_TABLE_INIT(Wifi_Radio_Config, if_name);
    OVSDB_TABLE_INIT(Wifi_VIF_Config, if_name);
    g_rconfs = ovsdb_table_select_where(&table_Wifi_Radio_Config, NULL, &g_num_rconfs);
    g_vconfs = ovsdb_table_select_where(&table_Wifi_VIF_Config, NULL, &g_num_vconfs);

    /* We need to rely on both netlink and hostapd events to track the DFS channel states
     * DFS states for channels that can be queried from driver - see nl80211_dfs_state:
     * NL80211_DFS_USABLE       -> OpenSync state NOP_FINISHED
     * NL80211_DFS_AVAILABLE    -> OpenSync state CAC_COMPLETED
     * NL80211_DFS_UNAVAILABLE  -> OpenSync state NOP_STARTED
     * DFS channel states from hostapd events:
     * DFS_EVENT_CAC_START      -> OpenSync state CAC_STARTED (CAC procedure started)
     * DFS_EVENT_CAC_COMPLETED  -> OpenSync state CAC_COMPLETED (CAC procedure completed)
     * DFS_EVENT_RADAR_DETECTED -> OpenSync state NOP_STARTED (Non occupancy period (NOP)
                                   active, making the channel unavailable)
     * DFS_EVENT_NOP_FINISHED   -> OpenSync state NOP_FINISHED (NOP is over,
                                   making the channel available again)
     * Any non-DFS channel      -> OpenSync state ALLOWED (channel available without restrictions)
     */
    nl_req_init_channels(&target_nl_global, NULL, g_chan_status);

    return true;
}

void nl_wm_deinit()
{
    netlink_deinit(&target_nl_global);
}
