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

#include "target_util.h"

/* libc */
#include <string.h>
#include <limits.h>
#include <netinet/in.h>
//#include <net/if.h>
//#include <linux/if_arp.h> /* ARPHRD_IEEE80211 */
#include <glob.h>
#include <inttypes.h>
#include <errno.h>

/* 3rd party */
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>
#include <linux/wireless.h>

/* opensync */
#include <ds_tree.h>
#include <memutil.h>
#include <util.h>
#include <const.h>
#include <os_nif.h>
#include <log.h>
#include <rq.h>
#include <nl.h>
#include <nl_80211.h>
#include <kconfig.h>

#include "target_util.h"
#include <cr_nl_cmd.h>
#include <mtk_ap_mld_info.h>
#include <mtk_sta_mld_info.h>
#include <mtk_assoc_req_frm.h>
#include <mtk_dfs_cac_req_frm.h>

/* osw */
#include <osw_drv.h>
#include <osw_state.h>
#include <osw_module.h>
#include <osw_drv_nl80211.h>
#include <osw_hostap.h>
#include <osw_drv_common.h>
#include <osw_time.h>
#include <osw_timer.h>
#include <ow_conf.h>
#include <osw_etc.h>

#define LOG_PREFIX(fmt, ...) \
    "osw: plat: cfg80211: " fmt, \
    ##__VA_ARGS__

#define LOG_PREFIX_PHY(phy_name, fmt, ...) \
    LOG_PREFIX("%s: " fmt, \
    phy_name, \
    ##__VA_ARGS__)

#define LOG_PREFIX_VIF(phy_name, vif_name, fmt, ...) \
    LOG_PREFIX_PHY(phy_name, "%s: " fmt, \
    vif_name, \
    ##__VA_ARGS__)

#define LOG_PREFIX_STA(phy_name, vif_name, sta_addr, fmt, ...) \
    LOG_PREFIX_VIF(phy_name, vif_name, OSW_HWADDR_FMT": " fmt, \
    OSW_HWADDR_ARG(sta_addr), \
    ##__VA_ARGS__)

#define BUFFER_SIZE 64

#include "osw_plat_cfg80211_drv_id.c.h"

/* This is the global module state. Anything
 * long-running (sockets, observers) should go
 * here.
 */
struct osw_plat_cfg80211 {
    struct osw_state_observer state_obs;
    struct osw_drv_nl80211_ops *nl_ops;
    struct osw_drv_nl80211_hook *nl_hook;
    struct osw_hostap *hostap;
    struct osw_hostap_hook *hostap_hook;
    struct osw_drv *drv_nl80211;
};

static bool
osw_plat_cfg80211_is_enabled(void)
{
    if (osw_etc_get("osw_plat_cfg80211_DISABLED")) return false;

    return true;
}

static bool
osw_plat_cfg80211_is_disabled(void)
{
    return osw_plat_cfg80211_is_enabled() == false;
}

static const char *
osw_plat_cfg80211_phy_to_special_vif(const char *phy_name)
{
    static const char *names[] = { "ra0", "rai0", "rax0" };
    size_t i;
    for (i = 0; i < ARRAY_SIZE(names); i++) {
        const char *path = strfmta("/sys/class/net/%s/phy80211/name", names[i]);
        char *name = strchomp(file_geta(path), "\n\t ");
        if (name && strcmp(name, phy_name) == 0) {
            return names[i];
        }
    }
    return NULL;
}

static void
osw_plat_cfg80211_report_sta_assoc_frm(struct osw_drv *drv,
                                       const char *phy_name,
                                       const char *vif_name,
                                       const struct osw_hwaddr *sta_addr)
{
    os_macaddr_t mac;
    memcpy(&mac.addr, sta_addr->octet, sizeof(sta_addr->octet));
    mtk_assoc_req_frm_fetcher_t *f = mtk_assoc_req_frm_fetcher(NULL, vif_name, &mac);
    while (mtk_assoc_req_frm_fetcher_run(f) == false) {}
    const struct osw_drv_vif_frame_rx rx = {
        .data = mtk_assoc_req_frm_fetcher_data(f),
        .len = mtk_assoc_req_frm_fetcher_len(f),
    };
    osw_drv_report_vif_frame_rx(drv, phy_name, vif_name, &rx);
    mtk_assoc_req_frm_fetcher_drop(&f);
}

static char *osw_plat_cfg80211_hostapd_get_status(const char *vif, const char *key)
{
    char *vif_status;
    const char *k;
    char *v = NULL;
    char *kv;

    vif_status = strexa("hostapd_cli", "-i", vif, "status");
    if (!vif_status || (!strlen(vif_status))) {
        LOGD("%s: failed to get vif status", vif);
        return v;
    }

    while ((kv = strsep(&vif_status, "\r\n"))) {
        if ((k = strsep(&kv, "=")) && (v = strsep(&kv, ""))) {
            if (!strcmp(k, key)) {
                LOGD("%s: get %s=%s from hostapd status", vif, key, v);
                return strdup(v);
            }
        }
    }
    return NULL;
}

static void
osw_plat_cfg80211_update_dfs_status(
        const char *phy_name,
        const char *vif_name,
        struct osw_drv_phy_state *state)
{
    char *cur_freq_str = NULL;
    char *freq_seg0_idx_str = NULL;
    char *oper_chwidth_str = NULL;
    char *vap_state = NULL;

    cur_freq_str = osw_plat_cfg80211_hostapd_get_status(vif_name, "freq");
    if (!cur_freq_str) goto end;
    const int cur_freq = atoi(cur_freq_str);
    if (osw_freq_to_band(cur_freq) != OSW_BAND_5GHZ) goto end;

    freq_seg0_idx_str = osw_plat_cfg80211_hostapd_get_status(vif_name, "vht_oper_centr_freq_seg0_idx");
    if (!freq_seg0_idx_str) goto end;
    const int freq_seg0_idx = atoi(freq_seg0_idx_str);

    oper_chwidth_str = osw_plat_cfg80211_hostapd_get_status(vif_name, "vht_oper_chwidth");
    if (!oper_chwidth_str) goto end;
    const int oper_chwidth = atoi(oper_chwidth_str);

    vap_state = osw_plat_cfg80211_hostapd_get_status(vif_name, "state");
    if (!vap_state) goto end;

    /* Calculate the current frequency range */
    int freq_min;
    int center_freq;
    int freq_max;

    /* center freq = 5 GHz + (5 * index) */
    center_freq = 5000 + 5 * freq_seg0_idx;

    mtk_dfs_cac_req_frm_fetcher_t *f = mtk_dfs_cac_req_frm_fetcher(NULL, vif_name);
    while (mtk_dfs_cac_req_frm_fetcher_run(f) == false) {}

    const int cac_active = mtk_dfs_cac_req_frm_fetcher_cac_active(f);
    const int ch_num = mtk_dfs_cac_req_frm_fetcher_ch_num(f);

    if (cac_active >= 0 && ch_num > 0) {
        center_freq = osw_chan_to_freq(OSW_BAND_5GHZ, ch_num);
    }
    mtk_dfs_cac_req_frm_fetcher_drop(&f);

    switch (oper_chwidth) {
        case OSW_HOSTAP_CONF_CHANWIDTH_80MHZ:
            freq_min = center_freq - 40;
            freq_max = center_freq + 40;
            break;
        case OSW_HOSTAP_CONF_CHANWIDTH_160MHZ:
            freq_min = center_freq - 80;
            freq_max = center_freq + 80;
            break;
        // TODO: More BW support
        case OSW_HOSTAP_CONF_CHANWIDTH_20MHZ_40MHZ:
        case OSW_HOSTAP_CONF_CHANWIDTH_80P80MHZ:
        case OSW_HOSTAP_CONF_CHANWIDTH_320MHZ:
            goto end;
    }

    const size_t n_cs = state->n_channel_states;
    size_t i;
    for (i = 0; i < n_cs; i++) {
        struct osw_channel_state *cs = &state->channel_states[i];
        const struct osw_channel *c = &cs->channel;

        if ((c->control_freq_mhz >= freq_min) &&
            (c->control_freq_mhz <= freq_max) &&
            (cac_active == 1)) {
                LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "cac start on %d"), c->control_freq_mhz);
                cs->dfs_state = OSW_CHANNEL_DFS_CAC_IN_PROGRESS;
        }
        
        if ((c->control_freq_mhz >= freq_min) &&
            (c->control_freq_mhz <= freq_max) &&
            (!strcmp(vap_state, "DFS"))) {
            LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "cac start on %d"), c->control_freq_mhz);
            cs->dfs_state = OSW_CHANNEL_DFS_CAC_IN_PROGRESS;
        }
    }

end:
    FREE(cur_freq_str);
    FREE(vap_state);
    FREE(oper_chwidth_str);
    FREE(freq_seg0_idx_str);
}

static void
osw_plat_logan_conf_vif_ap_acl(struct osw_drv_phy_config *phy,
                             struct osw_drv_vif_config *vif)
{
    struct osw_drv_vif_config_ap *ap = &vif->u.ap;
    if (ap->acl_changed == false) return;

    const char *vif_name = vif->vif_name;

    /* root@opensync:/# mwctl dev ra2 acl show_all
     * policy=2
     * root@opensync:/# */
    WARN_ON(strexa("mwctl", "dev", vif_name, "acl", "clear_all") == NULL);

    size_t i;
    for (i = 0; i < ap->acl.count; i++) {
        const struct osw_hwaddr *mac = &ap->acl.list[i];
        struct osw_hwaddr_str buf;
        const char *str = osw_hwaddr2str(mac, &buf);
        if (WARN_ON(str == NULL)) continue;
        WARN_ON(strexa("mwctl", "dev", vif_name, "acl", strfmta("add=%s", str)) == NULL);
    }
}

static void
osw_plat_logan_conf_vif_ap_acl_policy(struct osw_drv_phy_config *phy,
                                    struct osw_drv_vif_config *vif)
{
    struct osw_drv_vif_config_ap *ap = &vif->u.ap;
    if (ap->acl_policy_changed == false) return;

    const char *vif_name = vif->vif_name;
    switch (ap->acl_policy) {
        case OSW_ACL_NONE:
            WARN_ON(strexa("mwctl", "dev", vif_name, "acl", "policy=0") == NULL);
            break;
        case OSW_ACL_ALLOW_LIST:
            WARN_ON(strexa("mwctl", "dev", vif_name, "acl", "policy=1") == NULL);
            break;
        case OSW_ACL_DENY_LIST:
            WARN_ON(strexa("mwctl", "dev", vif_name, "acl", "policy=2") == NULL);
            break;
    }
}

static void
osw_plat_cfg80211_conf_each_vif(struct osw_drv_phy_config *phy,
                           struct osw_drv_vif_config *vif)
{
    (void)phy;
    (void)vif;

    switch (vif->vif_type) {
        case OSW_VIF_AP:
            if (osw_plat_cfg80211_has_mwctl(phy->phy_name)) {
                osw_plat_logan_conf_vif_ap_acl_policy(phy, vif);
                osw_plat_logan_conf_vif_ap_acl(phy, vif);
            }
            break;
        case OSW_VIF_AP_VLAN:
            break;
        case OSW_VIF_STA:
            break;
        case OSW_VIF_UNDEFINED:
            break;
    }
}

static void
osw_plat_cfg80211_conf_phy_enabled(struct osw_drv_phy_config *phy)
{
    if (phy->enabled_changed == false) return;

    const char *radio_vif = osw_plat_cfg80211_phy_to_special_vif(phy->phy_name);
    if (radio_vif != NULL) {
        WARN_ON(os_nif_up(radio_vif, phy->enabled) == false);
    }
}

static void
osw_plat_cfg80211_conf_each_phy(struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        osw_plat_cfg80211_conf_phy_enabled(phy);
        size_t j;
        for (j = 0; j < phy->vif_list.count; j++) {
            struct osw_drv_vif_config *vif = &phy->vif_list.list[j];
            osw_plat_cfg80211_conf_each_vif(phy, vif);
        }
    }
}

static bool
osw_plat_cfg80211_conf_need_vif_ap_disable(struct osw_drv_vif_config *vif)
{
    // use this function for configs that needs interface down
    return false;
}

static bool
osw_plat_cfg80211_conf_need_phy_disable(struct osw_drv_phy_config *phy)
{
    size_t i;
    for (i = 0; i < phy->vif_list.count; i++) {
        struct osw_drv_vif_config *vif = &phy->vif_list.list[i];
        switch (vif->vif_type) {
            case OSW_VIF_AP:
                if (osw_plat_cfg80211_conf_need_vif_ap_disable(vif))
                    return true;
                break;
            case OSW_VIF_AP_VLAN:
                break;
            case OSW_VIF_STA:
                // if (osw_plat_cfg80211_map_changed_for_vif(vif))
                //     return true;
                break;
            case OSW_VIF_UNDEFINED:
                break;
        }
    }

    return false;
}

static void
osw_plat_cfg80211_conf_disable_phys(struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;

        if (osw_plat_cfg80211_conf_need_phy_disable(phy)) {
            LOGI(LOG_PREFIX_PHY(phy_name, "disabling for reconfig"));
            // Need to put down logic to turn phy down, or change to down the specific vif
            // WARN_ON(strexa("ip", "link", "set", "dev", vif_name, "down") == NULL);
        }
    }
}

static void
osw_plat_cfg80211_conf_enable_phys(struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;

        if (phy->enabled) {
            if (osw_plat_cfg80211_conf_need_phy_disable(phy)) {
                LOGI(LOG_PREFIX_PHY(phy_name, "enabling after reconfig"));
            }
            // Need to put down logic to turn phy up, or change to up the specific vif
            // WARN_ON(strexa("ip", "link", "set", "dev", vif_name, "up") == NULL);
        }
    }
}

static const char *
osw_plat_cfg80211_ht40_offset_to_ext_chan_str(int ht40_offset)
{
    switch (ht40_offset)
    {
        case 1:
            return "ext_chan=above";
        case -1:
            return "ext_chan=below";
    }
    return "";
}

static const char *
osw_plat_mtk_ext_chan_str(const struct osw_channel *c)
{
    const enum osw_band band = osw_freq_to_band(c->control_freq_mhz);
    switch (band)
    {
        case OSW_BAND_2GHZ: /* fall through */
        case OSW_BAND_5GHZ:
            return osw_plat_cfg80211_ht40_offset_to_ext_chan_str(osw_channel_ht40_offset(c));
        case OSW_BAND_6GHZ:
            /* FIXME: MTK driver does not support proper center_freq0 parameter
             * For 6G 320Mhz they reuse ext_chan=above/below do determine how to set center_freq0. */
            if (c->control_freq_mhz < c->center_freq0_mhz) return "ext_chan=above";
            if (c->control_freq_mhz > c->center_freq0_mhz) return "ext_chan=below";
        case OSW_BAND_UNDEFINED:
            break;
    }
    return "";
}

static void
osw_plat_cfg80211_apply_csa(struct osw_plat_cfg80211 *m,
                            struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;
        if (osw_plat_cfg80211_drv_id_get(phy_name) != OSW_PLAT_CFG80211_DRV_ID_MTK_WIFI) continue;
        size_t j;
        for (j = 0; j < phy->vif_list.count; j++) {
            struct osw_drv_vif_config *vif = &phy->vif_list.list[j];
            const struct osw_channel *c = &vif->u.ap.channel;
            const char *vif_name = vif->vif_name;

            if (vif->vif_type != OSW_VIF_AP) continue;
            if (vif->u.ap.channel_changed == false) continue;

            LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "needs csa"));
            /* FIXME: implement tasker to schedule work async
             * reference commands:
             * mwctl phy <phyname> set channel [{num=<channel>|freq=<freq>}] [bw=<20|40|80|160|320>] [ext_chan=<below|above>] [ht_coex=<0|1>]
             * mwctl phy <phyname> set channel [bw=<20|40|80|160|320>] */
            WARN_ON(strexa("mwctl", "phy", phy_name, "set", "channel",
                    strfmta("freq=%d", c->control_freq_mhz),
                    strfmta("bw=%s", osw_channel_width_to_str(c->width)),
                    osw_plat_mtk_ext_chan_str(c)
                    ) == NULL);
            break;
        }
    }
}

static void
osw_plat_cfg80211_pre_request_config_cb(
        struct osw_drv_nl80211_hook *hook,
        struct osw_drv_conf *drv_conf,
        void *priv)
{
    struct osw_plat_cfg80211 *m = priv;
    osw_plat_cfg80211_apply_csa(m, drv_conf);

    osw_plat_cfg80211_conf_disable_phys(drv_conf);
    osw_plat_cfg80211_conf_each_phy(drv_conf);
    osw_plat_cfg80211_conf_enable_phys(drv_conf);

}

static bool
osw_plat_cfg80211_needs_scan_trigger(const char *phy_name)
{
    switch (osw_plat_cfg80211_drv_id_get(phy_name)) {
        case OSW_PLAT_CFG80211_DRV_ID_UNKNOWN:
            return false;
        case OSW_PLAT_CFG80211_DRV_ID_MT76:
            return false; /* maybe it does? not tested */
        case OSW_PLAT_CFG80211_DRV_ID_MTK_WIFI:
            /* FIXME: This is a temporary workaround
             * probably. The driver does introduce packet
             * drops and beacon loss even for on-chan scan
             * triggers. This is not production viable, but
             * good enough for bring up and testing eg.
             * reporting paths themselves.
             */
            return true;
    }
    return false;
}

struct osw_plat_cfg80211_find_up_vif {
    struct nl_80211 *nl;
    const struct nl_80211_vif *vif;
};

static void
osw_plat_cfg80211_pre_request_stats_bss_scan_each_vif(
        const struct nl_80211_vif *vif,
        void *priv)
{
    struct osw_plat_cfg80211_find_up_vif *result = priv;
    const struct osw_state_vif_info *info = osw_state_vif_lookup_by_vif_name(vif->name);
    if (result->vif == NULL && info != NULL) {
        bool up = false;
        const bool ok = os_nif_is_up(vif->name, &up);
        if (ok && up) {
            result->vif = vif;
        }
    }
}

static uint32_t
osw_plat_cfg80211_vif_get_oper_freq(const char *vif_name)
{
    const struct osw_state_vif_info *info = osw_state_vif_lookup_by_vif_name(vif_name);
    if (info != NULL) {
        return (osw_drv_vif_get_channel(info->drv_state)
                ?: osw_channel_none())->control_freq_mhz;
    }
    return 0;
}

static bool
osw_plat_cfg80211_nl_cmd_blocking(struct nl_msg **msg)
{
    cr_nl_cmd_t *cmd = cr_nl_cmd(NULL, NETLINK_GENERIC, *msg);
    *msg = NULL; /* msg is owned by cmd now */
    while (cr_nl_cmd_run(cmd) == false) {}
    {
        char buf[1024];
        cr_nl_cmd_log(cmd, buf, sizeof(buf));
        LOGT(LOG_PREFIX("%s", buf));
    }
    const bool ok = cr_nl_cmd_is_ok(cmd);
    cr_nl_cmd_drop(&cmd);
    return ok;
}

static struct nl_msg *
osw_plat_cfg80211_trigger_on_chan_scan_build(
        struct nl_80211 *nl,
        const struct nl_80211_phy *phy,
        const struct nl_80211_vif *vif)
{
    const char *phy_name = phy->name;
    const char *vif_name = vif->name;

    const uint32_t freq = osw_plat_cfg80211_vif_get_oper_freq(vif_name);
    if (freq == 0) return NULL;

    struct nl_msg *freqs = nlmsg_alloc();
    if (WARN_ON(freqs == NULL)) return NULL;

    int err = 0;
    struct nl_msg *msg = nl_80211_alloc_trigger_scan(nl, vif->ifindex);
    if (WARN_ON(msg == NULL)) goto cleanup;

    err |= nla_put_u32(freqs, 0, freq);
    err |= nla_put_nested(msg, NL80211_ATTR_SCAN_FREQUENCIES, freqs);
    freqs = NULL; /* freqs owned by msg now */
    if (WARN_ON(err != 0)) goto cleanup;

    LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "stats: trigger scan on %"PRIu32" expect tx/rx hiccups", freq));

    return msg;

cleanup:
    if (msg != NULL) nlmsg_free(msg);
    if (freqs != NULL) nlmsg_free(freqs);
    return NULL;
}

static void
osw_plat_cfg80211_trigger_on_chan_scan(
        struct nl_80211 *nl,
        const struct nl_80211_phy *phy,
        const struct nl_80211_vif *vif)
{
    struct nl_msg *msg = osw_plat_cfg80211_trigger_on_chan_scan_build(nl, phy, vif);
    if (msg == NULL) return;
    WARN_ON(osw_plat_cfg80211_nl_cmd_blocking(&msg) == false);
}

static void
osw_plat_cfg80211_pre_request_stats_bss_scan_each_phy(
        const struct nl_80211_phy *phy,
        void *priv)
{
    struct nl_80211 *nl = priv;

    if (osw_plat_cfg80211_needs_scan_trigger(phy->name)) {
        struct osw_plat_cfg80211_find_up_vif result = {
            .nl = nl,
            .vif = NULL, /* borrowed ref */
        };
        nl_80211_vif_each(
                nl,
                &phy->wiphy,
                osw_plat_cfg80211_pre_request_stats_bss_scan_each_vif, &result);

        if (result.vif != NULL) {
            osw_plat_cfg80211_trigger_on_chan_scan(nl, phy, result.vif);
        }
    }
}

static void
osw_plat_cfg80211_pre_request_stats_bss_scan(struct osw_plat_cfg80211 *m)
{
    struct nl_80211 *nl = m->nl_ops->get_nl_80211_fn(m->nl_ops);
    nl_80211_phy_each(
            nl,
            osw_plat_cfg80211_pre_request_stats_bss_scan_each_phy,
            nl);
}

static void
osw_plat_cfg80211_pre_request_stats_cb(
        struct osw_drv_nl80211_hook *hook,
        unsigned int stats_mask,
        void *priv)
{
    struct osw_plat_cfg80211 *m = priv;

    if (stats_mask & (1 << OSW_STATS_BSS_SCAN)) {
        /* FIXME: This may end up needing to be done in
         * osw_drv_nl80211 on best-effort basis, one way or
         * another. For now this is here. It may turn out
         * this isn't really necessary once we get driver(s)
         * fixed.
         */
        osw_plat_cfg80211_pre_request_stats_bss_scan(m);
    }
}

static void
osw_plat_cfg80211_drv_added_cb(
        struct osw_state_observer *obs,
        struct osw_drv *drv)
{
    struct osw_plat_cfg80211 *m = container_of(obs, struct osw_plat_cfg80211, state_obs);
    const struct osw_drv_ops *ops = osw_drv_get_ops(drv);
    const char *drv_name = ops->name;
    const bool is_nl80211 = (strstr(drv_name, "nl80211") != NULL);
    const bool is_not_nl80211 = !is_nl80211;

    if (is_not_nl80211) return;

    /* Knowing the osw_drv pointer of nl80211 makes it
     * possible to inject / supplement extra events as if
     * the nl80211 driver did it. For example probe_req
     * reports, channel switch changes, DFS events -- any
     * event that may be unavailable in the vendor's vanilla
     * nl80211 behavior.
     */
    m->drv_nl80211 = drv;

    LOGI(LOG_PREFIX("bound to nl80211"));
}

static void
osw_plat_cfg80211_drv_removed_cb(
        struct osw_state_observer *obs,
        struct osw_drv *drv)
{
    struct osw_plat_cfg80211 *m = container_of(obs, struct osw_plat_cfg80211, state_obs);
    const bool is_not_nl80211 = (m->drv_nl80211 != drv);

    if (is_not_nl80211) return;

    m->drv_nl80211 = NULL;
    LOGI(LOG_PREFIX("unbound from nl80211"));
}

static void
osw_plat_cfg80211_phy_added_cb(
        struct osw_state_observer *obs,
        const struct osw_state_phy_info *phy)
{
    const char *phy_name = phy->phy_name;
    LOGI(LOG_PREFIX_PHY(phy_name, "drv_id: %s", osw_plat_cfg80211_drv_id_to_cstr(osw_plat_cfg80211_drv_id_get(phy_name))));
}

static void
osw_plat_cfg80211_init(struct osw_plat_cfg80211 *m)
{
    const struct osw_state_observer obs = {
        .name = __FILE__,
        .drv_added_fn = osw_plat_cfg80211_drv_added_cb,
        .drv_removed_fn = osw_plat_cfg80211_drv_removed_cb,
        .phy_added_fn = osw_plat_cfg80211_phy_added_cb,
    };
    m->state_obs = obs;
}

static void
osw_plat_cfg80211_fix_phy_state_enabled(const char *phy_name, struct osw_drv_phy_state *state)
{
    const char *radio_vif = osw_plat_cfg80211_phy_to_special_vif(phy_name);
    if (radio_vif != NULL) {
        bool up = false;
        const bool ok = os_nif_is_up(radio_vif, &up);
        state->enabled = (ok && up);
    }
}

static void
osw_plat_cfg80211_fix_phy_state_cb(struct osw_drv_nl80211_hook *hook,
                                   const char *phy_name,
                                   struct osw_drv_phy_state *state,
                                   void *priv)
{
    char vif_list[512];
    char *vif, *p = vif_list;

    if (osw_plat_cfg80211_drv_id_is_unknown(phy_name)) return;

    if (!util_wifi_get_phy_all_vifs(phy_name, vif_list, sizeof(vif_list))) {
        while ((vif = strsep(&p, " "))) {
                osw_plat_cfg80211_update_dfs_status(phy_name, vif, state);
        }
    }

    /* WR: MT76 doesn't support RFKILL, the RFKILL from cloud 
     * also remove all the VIFs which means radio disabled can
     * be dummy, copy phy_conf->enabled to state.
     */
    const bool *phy_enabled = NULL;

    phy_enabled = ow_conf_phy_get_enabled(phy_name);
    if (phy_enabled)
        state->enabled = *phy_enabled;

    osw_plat_cfg80211_fix_phy_state_enabled(phy_name, state);
}

static void
osw_plat_cfg80211_fix_vif_ap_vlan_addrs(const char *phy_name,
                                   const char *vif_name,
                                   struct osw_drv_vif_state *state)
{
    char *stalist = strexa("iwinfo", vif_name, "assoclist");
    char *line;
    const char *macstr;

    if (osw_plat_cfg80211_drv_id_is_unknown(phy_name)) return;

    while ((line = strsep(&stalist, "\r\n"))) {
        if (line[0] == ' ')
            continue;

        macstr = strtok(line, " ");

        if (!macstr)
            continue;

        struct osw_hwaddr sta_addr;
        const bool mac_is_not_valid = (osw_hwaddr_from_cstr(macstr, &sta_addr) == false);
        if (mac_is_not_valid) return;

        struct osw_drv_vif_state_ap_vlan *ap_vlan = &state->u.ap_vlan;
        osw_hwaddr_list_append(&ap_vlan->sta_addrs, &sta_addr);
        return;
    }
}

static void
osw_plat_logan_fix_vif_ap_acl_policy(const char *phy_name,
                                   const char *vif_name,
                                   struct osw_drv_vif_state *state)
{
    struct osw_drv_vif_state_ap *ap = &state->u.ap;

    const char *buf = strexa("mwctl", "dev", vif_name, "acl", "show_all");

    if (WARN_ON(buf == NULL)) return;

    if (strstr(buf, "policy=0") != NULL) {
        ap->acl_policy = OSW_ACL_NONE;
    }
    if (strstr(buf, "policy=1") != NULL) {
        ap->acl_policy = OSW_ACL_ALLOW_LIST;
    }
    if (strstr(buf, "policy=2") != NULL) {
        ap->acl_policy = OSW_ACL_DENY_LIST;
    }
}

static void
osw_plat_logan_fix_vif_ap_acl(const char *phy_name,
                            const char *vif_name,
                            struct osw_drv_vif_state *state)
{
    struct osw_hwaddr_list *acl = &state->u.ap.acl;

    /*  root@opensync:/# mwctl dev ra1 acl show_all
     *  policy=1
     *  18:6a:81:ff:d4:55
     *  60:57:47:f6:e4:74
     *  root@opensync:/# */
    char *buf = strexa("mwctl", "dev", vif_name, "acl", "show_all");
    if (WARN_ON(acl == NULL)) return;
    if (WARN_ON(buf == NULL)) return;

    const char *word;
    while ((word = strsep(&buf, " \r\n")) != NULL) {
        struct osw_hwaddr mac;
        const bool valid = osw_hwaddr_from_cstr(word, &mac);
        if (valid) {
            const size_t i = acl->count;
            acl->count++;
            const size_t new_size = (acl->count * sizeof(*acl->list));
            acl->list = REALLOC(acl->list, new_size);
            acl->list[i] = mac;
        }
    }
}

static mtk_ap_mld_info_fetcher_t *
osw_plat_cfg80211_mtk_vif_to_mld_try(const char *vif_name, const bool single_ml_link)
{
    mtk_ap_mld_info_fetcher_t *f = mtk_ap_mld_info_fetcher(NULL, vif_name, single_ml_link);
    while (mtk_ap_mld_info_fetcher_run(f) == false) {}
    const struct mtk_ap_mld_info *mld = mtk_ap_mld_info_fetcher_get(f);
    if (mld != NULL) return f;
    mtk_ap_mld_info_fetcher_drop(&f);
    return NULL;
}

static mtk_ap_mld_info_fetcher_t *
osw_plat_cfg80211_mtk_vif_to_mld(const char *vif_name)
{
    static mtk_ap_mld_info_fetcher_t *f;

    f = osw_plat_cfg80211_mtk_vif_to_mld_try(vif_name, true);
    if (mtk_ap_mld_info_fetcher_get(f) != NULL) return f;
    mtk_ap_mld_info_fetcher_drop(&f);

    f = osw_plat_cfg80211_mtk_vif_to_mld_try(vif_name, false);
    if (mtk_ap_mld_info_fetcher_get(f) != NULL) return f;
    mtk_ap_mld_info_fetcher_drop(&f);

    return NULL;
}

static void
osw_plat_cfg80211_mtk_fix_ap_mld_addr(
        const char *phy_name,
        const char *vif_name,
        struct osw_drv_vif_state *state)
{
    mtk_ap_mld_info_fetcher_t *f = osw_plat_cfg80211_mtk_vif_to_mld(vif_name);
    const struct mtk_ap_mld_info *mld = mtk_ap_mld_info_fetcher_get(f);
    if (mld != NULL)
    {
        const size_t len = sizeof(mld->mld_addr.addr);
        memcpy(state->u.ap.mld.addr.octet, mld->mld_addr.addr, len);
    }
    mtk_ap_mld_info_fetcher_drop(&f);
}

static void
osw_plat_cfg80211_fix_vif_state_cb(
        struct osw_drv_nl80211_hook *hook,
        const char *phy_name,
        const char *vif_name,
        struct osw_drv_vif_state *state,
        void *priv)
{
    struct osw_drv_vif_sta_network *snet;
    struct osw_drv_vif_state_sta *ssta = &state->u.sta;

    if (osw_plat_cfg80211_drv_id_is_unknown(phy_name)) return;

    switch (state->vif_type) {
        case OSW_VIF_UNDEFINED:
            break;
        case OSW_VIF_AP:
            if (osw_plat_cfg80211_has_mwctl(phy_name)) {
                osw_plat_logan_fix_vif_ap_acl_policy(phy_name, vif_name, state);
                osw_plat_logan_fix_vif_ap_acl(phy_name, vif_name, state);
            }
            osw_plat_cfg80211_mtk_fix_ap_mld_addr(phy_name, vif_name, state);
            break;
        case OSW_VIF_AP_VLAN:
            osw_plat_cfg80211_fix_vif_ap_vlan_addrs(phy_name, vif_name, state);
            break;
        case OSW_VIF_STA:
            if (ssta->link.status == OSW_DRV_VIF_STATE_STA_LINK_CONNECTED) {
                for (snet = ssta->network; snet != NULL; snet = snet->next) {
                    if (memcmp(&snet->ssid, &ssta->link.ssid, sizeof(snet->ssid)) == 0) {
                        /* mirror multi_ap state from networks */
                        ssta->link.multi_ap = snet->multi_ap;
                        break;
                    }
                }
            }
            break;
    }
}

static void
osw_plat_cfg80211_mtk_fix_sta_mld_addr(const char *phy_name,
                                       const char *vif_name,
                                       const struct osw_hwaddr *sta_addr,
                                       struct osw_drv_sta_state *state)
{
    mtk_ap_mld_info_fetcher_t *f = osw_plat_cfg80211_mtk_vif_to_mld(vif_name);
    const struct mtk_ap_mld_info *mld = mtk_ap_mld_info_fetcher_get(f);
    if (mld != NULL)
    {
        os_macaddr_t mac;
        memcpy(&mac.addr, sta_addr->octet, sizeof(sta_addr->octet));
        mtk_sta_mld_info_fetcher_t *sf = mtk_sta_mld_info_fetcher(NULL, vif_name, mld->group_id, &mac);
        while (mtk_sta_mld_info_fetcher_run(sf) == false) {}
        const struct mtk_sta_mld_info *sta = mtk_sta_mld_info_fetcher_get(sf);
        if (sta != NULL)
        {
            const size_t len = sizeof(sta->mld_addr.addr);
            memcpy(state->mld_addr.octet, sta->mld_addr.addr, len);
        }
        mtk_sta_mld_info_fetcher_drop(&sf);
    }
    mtk_ap_mld_info_fetcher_drop(&f);
}

static void
osw_plat_cfg80211_fix_sta_state_cb(struct osw_drv_nl80211_hook *hook,
                                   const char *phy_name,
                                   const char *vif_name,
                                   const struct osw_hwaddr *sta_addr,
                                   struct osw_drv_sta_state *state,
                                   void *priv)
{
    osw_plat_cfg80211_mtk_fix_sta_mld_addr(phy_name, vif_name, sta_addr, state);
}

static struct osw_drv_phy_config *
osw_plat_cfg80211_drv_conf_lookup_phy_config(
        const char *phy_name,
        struct osw_drv_conf *drv_conf)
{
    size_t i;

    if (!drv_conf) return NULL;

    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy_conf = &drv_conf->phy_list[i];

        if (strcmp(phy_conf->phy_name, phy_name) == 0) {
            return phy_conf;
        }
    }

    return NULL;
}

static struct osw_drv_vif_config_ap *
osw_plat_cfg80211_phy_conf_lookup_ap_config(
        const char *vif_name,
        struct osw_drv_phy_config *phy_conf)
{
    size_t i;

    if (!phy_conf) return NULL;

    for (i = 0; i < phy_conf->vif_list.count; i++) {
        struct osw_drv_vif_config *vif_conf = &phy_conf->vif_list.list[i];

        if (strcmp(vif_conf->vif_name, vif_name) == 0 &&
            vif_conf->vif_type == OSW_VIF_AP)
            return &vif_conf->u.ap;
    }

    return NULL;
}

static void
osw_plat_cfg80211_ap_conf_mutate_mcast2ucast(
        struct osw_drv_vif_config_ap *ap_conf,
        struct osw_hostap_conf_ap_config *hapd_conf)
{
    OSW_HOSTAP_CONF_SET_VAL(hapd_conf->multicast_to_unicast, ap_conf->mcast2ucast);
}

static void
osw_plat_cfg80211_ap_conf_mutate_mtk(
        struct osw_drv_vif_config_ap *ap_conf,
        struct osw_hostap_conf_ap_config *hapd_conf)
{
    enum osw_band band = osw_freq_to_band(ap_conf->channel.control_freq_mhz);
    enum osw_channel_width width = ap_conf->channel.width;

    /* set htcaps for 2.4G and 5G ap config */
    if (ap_conf->mode.ht_enabled) {
        if ((band == OSW_BAND_2GHZ) || (band == OSW_BAND_5GHZ)) {
            STRSCAT(hapd_conf->ht_capab, "[LDPC][TX-STBC][RX-STBC1]");
            if (width == OSW_CHANNEL_20MHZ)
                STRSCAT(hapd_conf->ht_capab, "[SHORT-GI-20]");
            else if (width == OSW_CHANNEL_40MHZ)
                STRSCAT(hapd_conf->ht_capab, "[SHORT-GI-40]");
        }
    }

    /* set vhtcaps for 5G */
    if (ap_conf->mode.vht_enabled) {
        if (band == OSW_BAND_5GHZ) {
            OSW_HOSTAP_CONF_SET_BUF(hapd_conf->vht_capab, "");
            STRSCAT(hapd_conf->vht_capab, "[RXLDPC][TX-STBC-2BY1][RX-STBC-1][MAX-A-MPDU-LEN-EXP7]");
            if (width == OSW_CHANNEL_80MHZ)
                STRSCAT(hapd_conf->vht_capab, "[SHORT-GI-80][VHT80]");
            else if (width == OSW_CHANNEL_160MHZ)
                STRSCAT(hapd_conf->vht_capab, "[SHORT-GI-160][VHT160]");
        }
    }

    size_t len = sizeof(hapd_conf->extra_buf);
    char *buf = hapd_conf->extra_buf;

    if (band == OSW_BAND_6GHZ) {
        csnprintf(&buf, &len, "fils_discovery_max_interval=20\n");
    }

    if (ap_conf->mode.he_enabled) {
        csnprintf(&buf, &len, "he_su_beamformer=1\n");
    }

    csnprintf(&buf, &len, "tx_queue_data2_burst=5.9\n");
}

static void
osw_plat_cfg80211_hostap_conf_mutate_cb(
        struct osw_hostap_hook *hook,
        const char *phy_name,
        const char *vif_name,
        struct osw_drv_conf *drv_conf,
        struct osw_hostap_conf_ap_config *hapd_conf,
        void *priv)
{
    if (osw_plat_cfg80211_drv_id_is_unknown(phy_name)) return;

    struct osw_drv_phy_config *phy_conf = osw_plat_cfg80211_drv_conf_lookup_phy_config(phy_name, drv_conf);
    struct osw_drv_vif_config_ap *ap_conf = osw_plat_cfg80211_phy_conf_lookup_ap_config(vif_name, phy_conf);

    if (phy_conf == NULL) return;
    if (ap_conf == NULL) return;

    /* noscan is required for supporting HT40 in OpenWrt hostapd */
    OSW_HOSTAP_CONF_SET_VAL(hapd_conf->noscan, 1);
    OSW_HOSTAP_CONF_SET_VAL(hapd_conf->use_driver_iface_addr, 1);

    if (osw_plat_cfg80211_drv_id_get(phy_name) == OSW_PLAT_CFG80211_DRV_ID_MTK_WIFI) {
        /* HW sends probe response with mtk wifi driver */
        OSW_HOSTAP_CONF_SET_VAL(hapd_conf->send_probe_response, 0);
    } else {
        OSW_HOSTAP_CONF_SET_VAL(hapd_conf->send_probe_response, 1);
    }

    osw_plat_cfg80211_ap_conf_mutate_mcast2ucast(ap_conf, hapd_conf);

    if (osw_plat_cfg80211_drv_id_get(phy_name) == OSW_PLAT_CFG80211_DRV_ID_MT76) {
        osw_plat_cfg80211_ap_conf_mutate_mtk(ap_conf, hapd_conf);
    }
}

static void
osw_plat_cfg80211_invalidate_all_sta_links(struct osw_drv *drv,
                                           const char *vif_name,
                                           const struct osw_hwaddr *sta_addr)
{
    mtk_ap_mld_info_fetcher_t *f = osw_plat_cfg80211_mtk_vif_to_mld(vif_name);
    const struct mtk_ap_mld_info *mld = mtk_ap_mld_info_fetcher_get(f);
    if (mld != NULL) {
        os_macaddr_t mac;
        memcpy(&mac.addr, sta_addr->octet, sizeof(sta_addr->octet));
        mtk_sta_mld_info_fetcher_t *sf = mtk_sta_mld_info_fetcher(NULL, vif_name, mld->group_id, &mac);
        while (mtk_sta_mld_info_fetcher_run(sf) == false) {}
        const struct mtk_sta_mld_info *sta = mtk_sta_mld_info_fetcher_get(sf);
        if (sta != NULL) {
            size_t i;
            for (i = 0; i < ARRAY_SIZE(sta->links); i++) {
                if (sta->links[i].valid) {
                    struct osw_hwaddr link_sta_addr;
                    struct osw_hwaddr link_bssid;
                    const size_t len = sizeof(link_sta_addr.octet);
                    memcpy(link_sta_addr.octet, sta->links[i].link_addr.addr, len);
                    memcpy(link_bssid.octet, sta->links[i].link_bssid.addr, len);
                    const struct osw_state_vif_info *link_vif_info = osw_state_vif_lookup_by_mac_addr(&link_bssid);
                    if (link_vif_info != NULL) {
                        const char *link_vif_name = link_vif_info->vif_name;
                        const char *link_phy_name = link_vif_info->phy->phy_name;
                        osw_drv_report_sta_changed(drv, link_phy_name, link_vif_name, &link_sta_addr);
                    }
                }
            }
        }
        mtk_sta_mld_info_fetcher_drop(&sf);
    }
    mtk_ap_mld_info_fetcher_drop(&f);
}

static void
osw_plat_cfg80211_hostap_event_cb(
        struct osw_hostap_hook *hook,
        const char *phy_name,
        const char *vif_name,
        const char *msg,
        size_t msg_len,
        void *priv)
{
    struct osw_plat_cfg80211 *m = priv;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return;
    if (osw_plat_cfg80211_drv_id_is_unknown(phy_name)) return;

    char buf[1024];
    STRSCPY_WARN(buf, msg);

    char *p = buf;
    char *event_name = strsep(&p, " ");

    if ((strcmp(event_name, "BSS-TM-RESP") == 0) ||
        (strcmp(event_name, "BEACON-RESP-RX") == 0)) {
        LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "hostap event: %s (len=%zu)", msg, msg_len));
        char *token;
        while ((token = strsep(&p, " ")) != NULL) {
            const char *k = strsep(&token, "=");
            const char *v = strsep(&token, " ");

            if (strcmp(k, "raw") == 0) {
                size_t data_len = strlen(v)/2;
                uint8_t *data = MALLOC(sizeof(uint8_t) * data_len);
                const bool decoded = (hex2bin(v, strlen(v), data, data_len) != -1);

                if (decoded) {
                    const struct osw_drv_vif_frame_rx rx = {
                        .data = data,
                        .len = data_len,
                    };
                    osw_drv_report_vif_frame_rx(drv,
                                                phy_name,
                                                vif_name,
                                                &rx);
                }
                FREE(data);
                break;
            }
        }
    }

    if ((strcmp(event_name, "EAPOL-4WAY-HS-COMPLETED") == 0) ||
        (strcmp(event_name, "AP-STA-CONNECTED") == 0) ||
        (strcmp(event_name, "AP-STA-DISCONNECTED") == 0)) {
        const char *mac = strsep(&p, " ");
        struct osw_hwaddr addr;
        const bool addr_ok = osw_hwaddr_from_cstr(mac, &addr);
        if (addr_ok) {
            osw_plat_cfg80211_invalidate_all_sta_links(drv, vif_name, &addr);
            osw_plat_cfg80211_report_sta_assoc_frm(drv, phy_name, vif_name, &addr);
        }
    }
}

static void
osw_plat_cfg80211_start(struct osw_plat_cfg80211 *m)
{
    if (osw_plat_cfg80211_is_disabled()) return;

    static const struct osw_drv_nl80211_hook_ops nl_hook_ops = {
        .fix_phy_state_fn = osw_plat_cfg80211_fix_phy_state_cb,        
        .fix_vif_state_fn = osw_plat_cfg80211_fix_vif_state_cb,
        .fix_sta_state_fn = osw_plat_cfg80211_fix_sta_state_cb,
        .pre_request_config_fn = osw_plat_cfg80211_pre_request_config_cb,
        .pre_request_stats_fn = osw_plat_cfg80211_pre_request_stats_cb,
    };

    static const struct osw_hostap_hook_ops hapd_hook_ops = {
        .ap_conf_mutate_fn = osw_plat_cfg80211_hostap_conf_mutate_cb,
        .event_fn = osw_plat_cfg80211_hostap_event_cb,
    };

    struct ev_loop *loop = OSW_MODULE_LOAD(osw_ev);
    if (loop == NULL) return;

    m->nl_ops = OSW_MODULE_LOAD(osw_drv_nl80211);
    if (m->nl_ops == NULL) return;

    m->nl_hook = m->nl_ops->add_hook_ops_fn(m->nl_ops, &nl_hook_ops, m);
    if (WARN_ON(m->nl_hook == NULL)) return;

    m->hostap = OSW_MODULE_LOAD(osw_hostap);
    m->hostap_hook = osw_hostap_hook_alloc(m->hostap, &hapd_hook_ops, m);
    if (WARN_ON(m->hostap_hook == NULL)) return;

    osw_state_register_observer(&m->state_obs);
}

static struct osw_plat_cfg80211 g_osw_plat_cfg80211;

OSW_MODULE(osw_plat_cfg80211)
{
    struct osw_plat_cfg80211 *m = &g_osw_plat_cfg80211;
    osw_plat_cfg80211_init(m);
    osw_plat_cfg80211_start(m);
    return m;
}
