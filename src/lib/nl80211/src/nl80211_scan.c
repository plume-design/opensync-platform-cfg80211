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
#include "target_nl80211.h"
#include <string.h>

#include <ev.h>
#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

#define IEEE80211_GET_MODE_MASK    0x03
#define IEEE80211_SUPP_CHANWIDTH_SET_MASK 0x0000000C
#define IEEE80211_EXT_NSS_BWSUPP_MASK     0x000000C0

#define IEEE80211_HTINFO_CCFS2_GET_S     0x03
#define IEEE80211_HTINFO_CCFS2_SET_S     0x03

/* B2-B3 Supported Channel Width */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80      0x00000000  /* Does not support 160 or 80+80 */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160     0x00000004  /* Supports 160 */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160  0x00000008  /* Support both 160 or 80+80 */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_S       2           /* B2-B3 */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_MASK    0x0000000C

#define IEEE80211_VHTCAP_NO_EXT_NSS_BW_SUPPORT  0x00000000  /* B30-B31 Extended NSS Bandwidth Support */
#define IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_1   0x40000000  /* B30-B31 Extended NSS Bandwidth Support */
#define IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_2   0x80000000  /* B30-B31 Extended NSS Bandwidth Support */
#define IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_3   0xC0000000  /* B30-B31 Extended NSS Bandwidth Support */
#define IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_S   30
#define IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_MASK   0xC0000000

#define IEEE80211_VHTOP_CHWIDTH_REVSIG_160    1  /* 160 MHz Operating Channel (revised signalling) */
#define IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80  1  /* 80 + 80 MHz Operating Channel (revised signalling) */

#define IEEE80211_VHTCAP_EXT_NSS_MASK   (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_MASK | IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_MASK)

#define IEEE80211_EXTNSS_MAP_00_80F1_160NONE_80P80NONE      (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80 | IEEE80211_VHTCAP_NO_EXT_NSS_BW_SUPPORT)
#define IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE     (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80 | IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_1)
#define IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5    (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80 | IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_2)
#define IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75  (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80 | IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_3)
#define IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE        (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 | IEEE80211_VHTCAP_NO_EXT_NSS_BW_SUPPORT)
#define IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5       (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 | IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_1)
#define IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75      (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 | IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_2)
#define IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1          (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 | IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_3)
#define IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1          (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 | IEEE80211_VHTCAP_NO_EXT_NSS_BW_SUPPORT)
#define IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1          (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 | IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_3)

#define get_chanwidth_from_htmode(_offset) \
        (_offset == 0) ? RADIO_CHAN_WIDTH_20MHZ : \
        (_offset == 1) ? RADIO_CHAN_WIDTH_40MHZ_ABOVE : \
        (_offset == 3) ? RADIO_CHAN_WIDTH_40MHZ_BELOW : RADIO_CHAN_WIDTH_40MHZ

#define get_chanwidth_from_vhtmode(_opcw, _offset) \
        (_opcw == 0) ? get_chanwidth_from_htmode(_offset) : \
        (_opcw == 1) ? RADIO_CHAN_WIDTH_80MHZ : \
        (_opcw == 2) ? RADIO_CHAN_WIDTH_160MHZ : RADIO_CHAN_WIDTH_80_PLUS_80MHZ

#define get_chanwidth_from_hemode(_cwset, _opcw, _offset) \
        (_cwset == 0) ? get_chanwidth_from_vhtmode(_opcw, _offset) : \
        (_cwset == 1) ? RADIO_CHAN_WIDTH_160MHZ : \
        (_cwset == 3) ? RADIO_CHAN_WIDTH_80_PLUS_80MHZ : RADIO_CHAN_WIDTH_20MHZ

#define IS_REVSIG_VHT160_CHWIDTH(vht_op_chwidth, \
                                 vht_op_ch_freq_seg1, \
                                 vht_op_ch_freq_seg2) \
        ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) && \
        (vht_op_ch_freq_seg2 != 0) && \
        (abs(vht_op_ch_freq_seg2 - vht_op_ch_freq_seg1) == 8))

#define IS_REVSIG_VHT80_80_CHWIDTH(vht_op_chwidth, \
                                   vht_op_ch_freq_seg1, \
                                   vht_op_ch_freq_seg2) \
        ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) && \
        (vht_op_ch_freq_seg2 != 0) && \
        (abs(vht_op_ch_freq_seg2 - vht_op_ch_freq_seg1) > 16))

#define HTCCFS2_GET(ccfs2_1, ccfs2_2) \
        (((ccfs2_2) << IEEE80211_HTINFO_CCFS2_GET_S) | ccfs2_1)

#define GET_MODE(he, vht, ht) \
        (he) ? "HE" : (vht) ? "VHT" : (ht) ? "HT" : "None of the HT/VHT/HE"

struct ie_channel_info {
    uint32_t   vhtcap_info;
    uint8_t    vhtop_ch_freq_seg1;
    uint8_t    vhtop_ch_freq_seg2;
    uint8_t    vht_op_cw;
    uint8_t    ht_ccfs2_1;
    uint8_t    ht_ccfs2_2;
    uint8_t    sec_chan_offset;
    uint8_t    he_cw_set;
    bool       is_ht_found;
    bool       is_vht_found;
    bool       is_he_found;
};

struct parse_ies_data {
    unsigned char *ie;
    int ielen;
};

struct ie_parse {
    uint8_t has_parser;
    void (*parse)(const uint8_t type, uint8_t len, const uint8_t *data,
                const struct parse_ies_data *ie_buffer, struct ie_channel_info *info);
    uint8_t minlen;
    uint8_t maxlen;
};

static void parse_ht_oper(const uint8_t type, uint8_t len, const uint8_t *data,
                const struct parse_ies_data *ie_buffer, struct ie_channel_info *info)
{
    info->is_ht_found = true;
    info->sec_chan_offset = data[1] & IEEE80211_GET_MODE_MASK;
    info->ht_ccfs2_1 = (data[2] >> 5) & ((1 << 3) - 1);
    info->ht_ccfs2_2 = data[3] & ((1 << 5) - 1);
}

static void parse_vht_oper(const uint8_t type, uint8_t len, const uint8_t *data,
                const struct parse_ies_data *ie_buffer, struct ie_channel_info *info)
{
    info->is_vht_found = true;
    info->vht_op_cw = data[0];
    info->vhtop_ch_freq_seg1 = data[1];
    info->vhtop_ch_freq_seg2 = data[2];
}

static void parse_vht_capa(const uint8_t type, uint8_t len, const uint8_t *data,
                const struct parse_ies_data *ie_buffer, struct ie_channel_info *info)
{
    info->is_vht_found = true;
    info->vhtcap_info = (data[0] & IEEE80211_SUPP_CHANWIDTH_SET_MASK) |
                        ((data[3] & IEEE80211_EXT_NSS_BWSUPP_MASK) << 24);
}

static void parse_he_capa(const uint8_t type, uint8_t len, const uint8_t *data,
                const struct parse_ies_data *ie_buffer, struct ie_channel_info *info)
{
    info->is_he_found = true;
    info->he_cw_set = (data[6] >> 3) & IEEE80211_GET_MODE_MASK;
}

static const struct ie_parse ieparsers[] = {
    [61] = { 1, parse_ht_oper, 22, 22, },
    [191] = { 1, parse_vht_capa, 12, 255, },
    [192] = { 1, parse_vht_oper, 5, 255, },
};

static const struct ie_parse ext_parsers[] = {
    [35] = { 1,  parse_he_capa, 21, 54, },
};

static void parse_ie(const struct ie_parse *p, const uint8_t type, uint8_t len,
            const uint8_t *data,
            const struct parse_ies_data *ie_buffer,
            struct ie_channel_info *info
        )
{
    if (!p->parse)
        return;

    if (len < p->minlen || len > p->maxlen) {
        if (len > 1) {
            LOGT("<invalid: %d bytes:", len);
        } else if (len)
            LOGT("<invalid: 1 byte: %.02x>", data[0]);
        else
            LOGT("<invalid: no data>");
        return;
    }

    p->parse(type, len, data, ie_buffer, info);
}

static void parse_extension(unsigned char len, unsigned char *ie,
                            struct ie_channel_info *info)
{
    unsigned char tag;

    if (len < 1) {
        LOGD("Extension IE: <empty");
        return;
    }

    tag = ie[0];
    if (tag < ARRAY_SIZE(ext_parsers) && ext_parsers[tag].has_parser) {
        parse_ie(&ext_parsers[tag], tag, len - 1, ie + 1, NULL, info);
        return;
    }
}

static uint8_t
util_extnss_160_validate(uint32_t vhtcap,
                         uint8_t vht_op_chwidth,
                         uint8_t vht_op_ch_freq_seg1,
                         uint8_t vht_op_ch_freq_seg2,
                         uint8_t ccfs2_1,
                         uint8_t ccfs2_2)
{

    if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK)
        == IEEE80211_EXTNSS_MAP_00_80F1_160NONE_80P80NONE)) {
        return 0;
    }

    if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
        if ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) &&
               (vht_op_ch_freq_seg2 != 0) &&
               (abs(vht_op_ch_freq_seg2 - vht_op_ch_freq_seg1) == 8)) {
            return 1;
        }
    } else if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75)) {
        if ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) &&
               (HTCCFS2_GET(ccfs2_1, ccfs2_2) != 0) &&
               (abs(HTCCFS2_GET(ccfs2_1, ccfs2_2) - vht_op_ch_freq_seg1) == 8)) {
            return 2;
        }
    } else {
        return 0;
    }
    return 0;
}

static uint8_t
util_extnss_80p80_validate(uint32_t vhtcap,
                           uint8_t vht_op_chwidth,
                           uint8_t vht_op_ch_freq_seg1,
                           uint8_t vht_op_ch_freq_seg2,
                           uint8_t ccfs2_1,
                           uint8_t ccfs2_2)
{

    if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK)
        == IEEE80211_EXTNSS_MAP_00_80F1_160NONE_80P80NONE)) {
        return 0;
    }

    if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
        if ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) &&
               (vht_op_ch_freq_seg2 != 0) &&
               (abs(vht_op_ch_freq_seg2 - vht_op_ch_freq_seg1) > 16)) {
            return 1;
        }
    } else if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75)) {
        if ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) &&
               (HTCCFS2_GET(ccfs2_1, ccfs2_2) != 0) &&
               (abs(HTCCFS2_GET(ccfs2_1, ccfs2_2) - vht_op_ch_freq_seg1) > 16)) {
             return 2;
        }
    } else {
        return 0;
    }
    return 0;
}

static uint8_t
util_get_chanwidth(struct ie_channel_info *info)
{
    bool       is_ht_found        = info->is_ht_found;
    bool       is_vht_found       = info->is_ht_found;
    bool       is_he_found        = info->is_he_found;
    uint8_t    ht_ccfs2_1         = info->ht_ccfs2_1;
    uint8_t    ht_ccfs2_2         = info->ht_ccfs2_2;
    uint8_t    sec_chan_offset    = info->sec_chan_offset;
    uint8_t    vht_op_cw          = info->vht_op_cw;
    uint8_t    he_cw_set          = info->he_cw_set;
    uint32_t   vhtcap_info        = info->vhtcap_info;
    uint8_t    vhtop_ch_freq_seg1 = info->vhtop_ch_freq_seg1;
    uint8_t    vhtop_ch_freq_seg2 = info->vhtop_ch_freq_seg2;
    uint8_t    chanwidth          = 0;

    LOG(TRACE,
        "Neighbor is AP Operating on %s Mode "
        "{Secondary channel offset - %u"
        " ccfs2_1 - %u ccfs2_2 - %u"
        " VHT Capabilities info - 0x%08x"
        " VHT operational chanwidth - %u"
        " CCS0 - %u CCS1 - %u"
        " HE chanwidth set - %u}",
        GET_MODE(is_he_found, is_vht_found, is_ht_found),
        sec_chan_offset,
        ht_ccfs2_1,
        ht_ccfs2_2,
        vhtcap_info,
        vht_op_cw,
        vhtop_ch_freq_seg1,
        vhtop_ch_freq_seg2,
        he_cw_set);

    /* If neighbor AP is not running on any of HT/VHT/HE modes then
       the default channel width is 20 MHz */
    if (is_he_found) {
        chanwidth = get_chanwidth_from_hemode(he_cw_set,
                                              vht_op_cw,
                                              sec_chan_offset);
    } else if (is_vht_found) {
        chanwidth = get_chanwidth_from_vhtmode(vht_op_cw, sec_chan_offset);
    } else if (is_ht_found) {
        return get_chanwidth_from_htmode(sec_chan_offset);
    } else {
        return RADIO_CHAN_WIDTH_20MHZ;
    }

    if (chanwidth == RADIO_CHAN_WIDTH_80MHZ) {
        if ( util_extnss_160_validate(vhtcap_info,
                                      vht_op_cw,
                                      vhtop_ch_freq_seg1,
                                      vhtop_ch_freq_seg2,
                                      ht_ccfs2_1,
                                      ht_ccfs2_2)
            || IS_REVSIG_VHT160_CHWIDTH(vht_op_cw,
                                        vhtop_ch_freq_seg1,
                                        vhtop_ch_freq_seg2 ) ) {
            return RADIO_CHAN_WIDTH_160MHZ;
        } else if ( util_extnss_80p80_validate(vhtcap_info,
                                               vht_op_cw,
                                               vhtop_ch_freq_seg1,
                                               vhtop_ch_freq_seg2,
                                               ht_ccfs2_1,
                                               ht_ccfs2_2)
            || IS_REVSIG_VHT80_80_CHWIDTH(vht_op_cw,
                                          vhtop_ch_freq_seg1,
                                          vhtop_ch_freq_seg2) ) {
            return RADIO_CHAN_WIDTH_80_PLUS_80MHZ;
        } else {
            return RADIO_CHAN_WIDTH_80MHZ;
        }
    } else {
        return chanwidth;
    }
}

int nl80211_scan_cmp(void *_a, void  *_b)
{
    struct nl80211_scan *a = _a;
    struct nl80211_scan *b = _b;

    return strcmp(a->name, b->name);
}

ds_tree_t  nl80211_scan_tree = DS_TREE_INIT(nl80211_scan_cmp, struct nl80211_scan, if_node);

static int nl80211_scan_trigger_recv(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

static int nl80211_scan_add(char *name, target_scan_cb_t *scan_cb, void *scan_ctx)
{
    struct nl80211_scan *nl80211_scan = ds_tree_find(&nl80211_scan_tree, name);

    if (!nl80211_scan) {
        nl80211_scan = malloc(sizeof(*nl80211_scan));
        if (!nl80211_scan)
            return -EINVAL;
        memset(nl80211_scan, 0, sizeof(*nl80211_scan));
        STRSCPY(nl80211_scan->name, name);
        nl80211_scan->if_node.otn_key = nl80211_scan->name;
        ds_tree_insert(&nl80211_scan_tree, nl80211_scan, nl80211_scan->name);
        LOGT("%s: added scan context", name);
    }

    nl80211_scan->scan_cb = scan_cb;
    nl80211_scan->scan_ctx = scan_ctx;
    return 0;
}

int nl80211_scan_trigger(struct nl_global_info *nl_sm_global,
                         char *ifname, uint32_t *chan_list, uint32_t chan_num,
                         int dwell_time, radio_scan_type_t scan_type,
                         target_scan_cb_t *scan_cb, void *scan_ctx)
{
    int if_index;
    struct nl_msg *msg;
    struct nlattr *freq;
    unsigned int i, flags = 0;
    int ret = 0;

    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_TRIGGER_SCAN, false);
    if (!msg)
        return -EINVAL;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    LOGT("%s: not setting dwell time\n", ifname);

    /* Add the ap-force flag, otherwise the scan fails on wifi6 APs */
    flags |= NL80211_SCAN_FLAG_AP;
    nla_put(msg, NL80211_ATTR_SCAN_FLAGS, sizeof(uint32_t), &flags);

    freq = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
    for (i = 0; i < chan_num; i++)
         nla_put_u32(msg, i, util_chan_to_freq(chan_list[i]));
    nla_nest_end(msg, freq);

    ret = nl80211_scan_add(ifname, scan_cb, scan_ctx);
    if (ret)
    {
        LOG(ERR,"%s: scan add failed %d\n", ifname, ret);
        return -EINVAL;
    }

    ret = nlmsg_send_and_recv(nl_sm_global, msg, nl80211_scan_trigger_recv, NULL);
    if (ret)
        LOG(ERR, "%s: scan request failed %d\n", ifname, ret);

    return ret;
}

bool nl80211_stats_scan_start(radio_entry_t *radio_cfg, uint32_t *chan_list,
                              uint32_t chan_num, radio_scan_type_t scan_type,
                              int32_t dwell_time, target_scan_cb_t *scan_cb,
                              void *scan_ctx)
{
    struct nl_global_info *nl_sm_global = get_nl_sm_global();
    char *ifname = radio_cfg->if_name;
    bool ret = true;

    if (nl80211_scan_trigger(nl_sm_global, ifname, chan_list, chan_num,
                                dwell_time, scan_type, scan_cb, scan_ctx) < 0)
        ret = false;
    LOGT("%s: scan trigger returned %d", radio_cfg->if_name, ret);

    if (ret == false)
        LOG(ERR, "%s: failed to trigger scan, aborting", radio_cfg->if_name);

    return ret;
}

static int nl80211_scan_abort_recv(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

struct nl80211_scan *nl80211_scan_find(char *name)
{
    struct nl80211_scan *nl80211_scan = ds_tree_find(&nl80211_scan_tree, name);

    if (!nl80211_scan)
        LOGN("%s: scan context does not exist", name);

    return nl80211_scan;
}

void nl80211_scan_del(struct nl80211_scan *nl80211_scan)
{
    LOGT("%s: delete scan context", nl80211_scan->name);
    ev_async_stop(EV_DEFAULT, &nl80211_scan->async);
    ds_tree_remove(&nl80211_scan_tree, nl80211_scan);
    free(nl80211_scan);
}

void nl80211_scan_finish(char *name, bool state)
{
    struct nl80211_scan *nl80211_scan = nl80211_scan_find(name);

    if (nl80211_scan) {
        LOGN("%s: calling context cb", nl80211_scan->name);
        (*nl80211_scan->scan_cb)(nl80211_scan->scan_ctx, state);
        nl80211_scan_del(nl80211_scan);
    }
}

int nl80211_scan_abort(struct nl_global_info *nl_sm_global, char *ifname)
{
    int if_index;
    struct nl_msg *msg;
    struct nl80211_scan *nl80211_scan;

    nl80211_scan = nl80211_scan_find(ifname);
    if ((if_index = util_sys_ifname_to_idx(ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_ABORT_SCAN, false);
    if (!msg) {
        return -EINVAL;
    }
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    if (nl80211_scan)
        nl80211_scan_del(nl80211_scan);

    return nlmsg_send_and_recv(nl_sm_global, msg, nl80211_scan_abort_recv, NULL);
}

bool nl80211_stats_scan_stop(radio_entry_t *radio_cfg,
                             radio_scan_type_t scan_type)
{
    struct nl_global_info *nl_sm_global = get_nl_sm_global();
    char *ifname = radio_cfg->if_name;
    bool ret = true;

    if (nl80211_scan_abort(nl_sm_global, ifname) < 0)
        ret = false;

    LOGT("%s: scan abort returned %d", radio_cfg->if_name, ret);

    return true;
}

static int nl80211_scan_dump_recv(struct nl_msg *msg, void *arg)
{
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_TSF]                  = { .type = NLA_U64 },
        [NL80211_BSS_FREQUENCY]            = { .type = NLA_U32 },
        [NL80211_BSS_BSSID]                = { 0 },
        [NL80211_BSS_BEACON_INTERVAL]      = { .type = NLA_U16 },
        [NL80211_BSS_CAPABILITY]           = { .type = NLA_U16 },
        [NL80211_BSS_INFORMATION_ELEMENTS] = { 0 },
        [NL80211_BSS_SIGNAL_MBM]           = { .type = NLA_U32 },
        [NL80211_BSS_SIGNAL_UNSPEC]        = { .type = NLA_U8  },
        [NL80211_BSS_STATUS]               = { .type = NLA_U32 },
        [NL80211_BSS_SEEN_MS_AGO]          = { .type = NLA_U32 },
        [NL80211_BSS_BEACON_IES]           = { 0 },
    };
    struct nl_call_param *nl_call_param = (struct nl_call_param *)arg;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    dpp_neighbor_record_list_t *neighbor;
    struct ie_channel_info chan_info;

    memset(&chan_info, 0, sizeof(struct ie_channel_info));
    memset(tb, 0, sizeof(tb));
    memset(bss, 0, sizeof(bss));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_BSS] ||
            nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy) ||
            !bss[NL80211_BSS_BSSID])
        return NL_OK;

    neighbor = dpp_neighbor_record_alloc();
    neighbor->entry.type = nl_call_param->type;
    if (bss[NL80211_BSS_TSF])
        neighbor->entry.tsf = nla_get_u64(bss[NL80211_BSS_TSF]);
    if (bss[NL80211_BSS_FREQUENCY])
        neighbor->entry.chan =
                    util_freq_to_chan((int)nla_get_u32(bss[NL80211_BSS_FREQUENCY]));
    if (bss[NL80211_BSS_SIGNAL_MBM])
        neighbor->entry.sig = ((int) nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM])) / 100;
    /*
        TODO: At this time, we report signal as SNR by using fixed noise floor.
        Need to revise the implementation to support dynamic noise floor in
        opensync 2.2 and above.
    */
    /* Convert to SNR before sending to cloud */
    neighbor->entry.sig -= DEFAULT_NOISE_FLOOR;

    /* Prevent sending negative values */
    if (neighbor->entry.sig < 0) {
        LOGT("Found negative signal/noise ratio %d, forcing value to 0", neighbor->entry.sig);
        neighbor->entry.sig = 0;
    }
    if (bss[NL80211_BSS_SEEN_MS_AGO])
        neighbor->entry.lastseen = nla_get_u32(bss[NL80211_BSS_SEEN_MS_AGO]);
    if (bss[NL80211_BSS_BSSID]) {
        mac_dump(neighbor->entry.bssid, nla_data(bss[NL80211_BSS_BSSID]));
        LOGT("Parsed %s BSSID %s",
             radio_get_name_from_type(nl_call_param->type),neighbor->entry.bssid);
    }

    if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        int bssielen = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        unsigned char *bssie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        int len;

        struct parse_ies_data ie_buffer = {
            .ie = bssie,
            .ielen = bssielen
        };

        while (bssielen >= 2 && bssielen >= bssie[1]) {
            if ((bssie[0] < ARRAY_SIZE(ieparsers)) &&
                (ieparsers[bssie[0]].has_parser == 1))
            {
                parse_ie(&ieparsers[bssie[0]],
                            bssie[0], bssie[1], bssie + 2, &ie_buffer, &chan_info);
            } else if (bssie[0] == 0 || bssie[0] == 114) {
                /* SSID or Mesh ID */
                len = min(bssie[1], 32 + 1);
                memcpy(neighbor->entry.ssid, bssie + 2, len);
                neighbor->entry.ssid[len] = 0;
            } else if (bssie[0] == 255) {
                /* extension */
                parse_extension(bssie[1], bssie + 2, &chan_info);
            }
            bssielen -= bssie[1] + 2;
            bssie += bssie[1] + 2;
        }
    }
    /* get chanwidth from IEs */
    neighbor->entry.chanwidth = util_get_chanwidth(&chan_info);
    LOGT("%s Parsed %s SSID %s chan %d chanwidth %d signal %d",
        __func__,
         radio_get_name_from_type(nl_call_param->type),
         neighbor->entry.ssid,
         neighbor->entry.chan,
         neighbor->entry.chanwidth,
         neighbor->entry.sig);

    ds_dlist_insert_tail(nl_call_param->list, neighbor);
    return NL_OK;
}

int nl80211_scan_dump(struct nl_global_info *nl_sm_global,
                      struct nl_call_param *nl_call_param)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(nl_call_param->ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_GET_SCAN, true);
    if (!msg) {
        return -EINVAL;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    return nlmsg_send_and_recv(nl_sm_global, msg, nl80211_scan_dump_recv, nl_call_param);
}

bool nl80211_stats_scan_get(radio_entry_t *radio_cfg, uint32_t *chan_list,
                            uint32_t chan_num, radio_scan_type_t scan_type,
                            dpp_neighbor_report_data_t *scan_results)
{
    struct nl_global_info *nl_sm_global = get_nl_sm_global();
    struct nl_call_param nl_call_param = {
        .ifname = radio_cfg->if_name,
        .type = radio_cfg->type,
        .list = &scan_results->list,
    };
    bool ret = true;

    if (nl80211_scan_dump(nl_sm_global, &nl_call_param) < 0)
        ret = false;

    LOGT("Parsed %s %s scan results for channel %d",
         radio_get_name_from_type(radio_cfg->type),
         radio_get_scan_name_from_type(scan_type),
         chan_list[0]);
    return ret;
}
