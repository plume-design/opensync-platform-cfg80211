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

#include <const.h>
#include <log.h>

#include <linux/nl80211.h>
#include <mtk_vendor_nl80211_copy.h>
#include <netlink/genl/genl.h>

#include <mtk_vendor_cmd.h>

struct nl_msg *mtk_vendor_cmd_msg(const int family_id, const int subcmd_id, const int ifindex)
{
    struct nl_msg *msg = nlmsg_alloc();
    const int genl_flags = 0;
    const int genl_cmd = NL80211_CMD_VENDOR;
    const int hdrlen = 0;
    const int version = 0;
    int err = 0;
    err |= (genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, hdrlen, genl_flags, genl_cmd, version) == NULL);
    err |= nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    err |= nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MTK_NL80211_VENDOR_ID);
    err |= nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, subcmd_id);
    if (err)
    {
        nlmsg_free(msg);
        msg = NULL;
    }
    return msg;
}

struct nl_msg *mtk_vendor_cmd_get_ap_mld_msg(const int family_id, const int ifindex, const os_macaddr_t *mac)
{
    if (family_id < 0) return NULL;
    if (ifindex == 0) return NULL;

    const int subcmd = MTK_NL80211_VENDOR_SUBCMD_GET_AP_MLD;
    struct nl_msg *msg = mtk_vendor_cmd_msg(family_id, subcmd, ifindex);
    if (WARN_ON(msg == NULL)) return NULL;
    int err = 0;

    {
        void *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
        if (mac)
        {
            const size_t len = sizeof(mac->addr);
            err |= nla_put(msg, MTK_NL80211_VENDOR_ATTR_AP_MLD_ADDRESS, len, mac->addr);
        }
        else
        {
            err |= nla_put_flag(msg, MTK_NL80211_VENDOR_ATTR_AP_MLD_DUMP);
        }
        err |= nla_nest_end(msg, data);
    }

    if (err)
    {
        nlmsg_free(msg);
        msg = NULL;
    }

    return msg;
}

bool mtk_vendor_cmd_get_ap_mld_parse(
        struct nl_msg *resp,
        unsigned int *group_id,
        os_macaddr_t *mld_addr,
        struct nlattr **aps_attr)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    int err = 0;

    err = genlmsg_parse(nlmsg_hdr(resp), 0, tb, ARRAY_SIZE(tb) - 1, NULL);
    if (err) return false;

    struct nlattr *vendor_data = tb[NL80211_ATTR_VENDOR_DATA];
    if (vendor_data == NULL) return false;

    struct nlattr *vendor_tb[MTK_NL80211_VENDOR_ATTR_AP_MLD_ATTR_MAX + 1];
    err = nla_parse_nested(vendor_tb, ARRAY_SIZE(vendor_tb) - 1, vendor_data, NULL);
    if (err) return false;

    struct nlattr *id = vendor_tb[MTK_NL80211_VENDOR_ATTR_AP_MLD_INDEX];
    struct nlattr *addr = vendor_tb[MTK_NL80211_VENDOR_ATTR_AP_MLD_ADDRESS];
    struct nlattr *aps = vendor_tb[MTK_NL80211_VENDOR_ATTR_AP_MLD_AFFILIATED_APS];
    if (id == NULL) return false;
    if (addr == NULL) return false;
    if (WARN_ON(nla_len(id) != sizeof(uint8_t))) return false;
    if (WARN_ON(nla_len(addr) != sizeof(mld_addr->addr))) return false;

    if (group_id != NULL) *group_id = nla_get_u8(id);
    if (mld_addr != NULL) memcpy(mld_addr->addr, nla_data(addr), nla_len(addr));
    if (aps_attr != NULL) *aps_attr = aps;

    return true;
}

bool mtk_vendor_cmd_get_ap_mld_parse_ap(struct nlattr *ap, unsigned int *link_id, os_macaddr_t *link_addr)
{
    struct nlattr *tb[MTK_NL80211_VENDOR_ATTR_AP_MLD_ATTR_MAX + 1];
    const int err = nla_parse_nested(tb, ARRAY_SIZE(tb) - 1, ap, NULL);
    if (err) return false;

    struct nlattr *id = tb[MTK_NL80211_VENDOR_ATTR_AP_MLD_AFFILIATED_AP_LINKID];
    struct nlattr *bssid = tb[MTK_NL80211_VENDOR_ATTR_AP_MLD_AFFILIATED_AP_BSSID];
    if (id == NULL) return false;
    if (bssid == NULL) return false;
    if (WARN_ON(nla_len(id) != sizeof(uint8_t))) return false;
    if (WARN_ON(nla_len(bssid) != sizeof(link_addr->addr))) return false;
    if (link_id != NULL) *link_id = nla_get_u8(id);
    if (link_addr != NULL) memcpy(link_addr->addr, nla_data(bssid), nla_len(bssid));

    return true;
}

struct nl_msg *mtk_vendor_cmd_get_sta_mld_msg(const int family_id, const int ifindex, const int mld_group_id)
{
    if (family_id < 0) return NULL;
    if (ifindex == 0) return NULL;

    const int subcmd = MTK_NL80211_VENDOR_SUBCMD_GET_CONNECTED_STA_MLD;
    struct nl_msg *msg = mtk_vendor_cmd_msg(family_id, subcmd, ifindex);
    if (WARN_ON(msg == NULL)) return NULL;
    int err = 0;

    {
        void *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
        if (mld_group_id > 0)
        {
            err |= nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_AP_MLD_INDEX_TO_DUMP, mld_group_id);
            /* Will request clients on a given MLD group,
             * regardless if it's a multi-link or a
             * single-link MLD group.
             */
        }
        else
        {
            /* Will request all clients, from all multi-link
             * MLD groups. It will _not_ report MLD
             * associations from single-link MLD groups.
             */
        }
        err |= nla_nest_end(msg, data);
    }

    if (err)
    {
        nlmsg_free(msg);
        msg = NULL;
    }

    return msg;
}

bool mtk_vendor_cmd_get_sta_mld_parse(
        struct nl_msg *resp,
        unsigned int *group_id,
        os_macaddr_t *mld_addr,
        struct nlattr **stas_attr)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    int err = 0;

    err = genlmsg_parse(nlmsg_hdr(resp), 0, tb, ARRAY_SIZE(tb) - 1, NULL);
    if (err) return false;

    struct nlattr *vendor_data = tb[NL80211_ATTR_VENDOR_DATA];
    if (vendor_data == NULL) return false;

    struct nlattr *vendor_tb[MTK_NL80211_VENDOR_ATTR_CONNECTED_STA_MLD_MAX + 1];
    err = nla_parse_nested(vendor_tb, ARRAY_SIZE(vendor_tb) - 1, vendor_data, NULL);
    if (err) return false;

    struct nlattr *id = vendor_tb[MTK_NL80211_VENDOR_ATTR_AP_MLD_INDEX_TO_DUMP];
    struct nlattr *addr = vendor_tb[MTK_NL80211_VENDOR_ATTR_CONNECTED_STA_MLD_MAC];
    struct nlattr *stas = vendor_tb[MTK_NL80211_VENDOR_ATTR_CONNECTED_STA_MLD_AFFILIATED_STA];
    if (id == NULL) return false;
    if (addr == NULL) return false;
    if (WARN_ON(nla_len(id) != sizeof(uint8_t))) return false;
    if (WARN_ON(nla_len(addr) != sizeof(mld_addr->addr))) return false;

    if (group_id != NULL) *group_id = nla_get_u8(id);
    if (mld_addr != NULL) memcpy(mld_addr->addr, nla_data(addr), nla_len(addr));
    if (stas_attr != NULL) *stas_attr = stas;

    return true;
}

bool mtk_vendor_cmd_get_sta_mld_parse_sta(
        struct nlattr *sta,
        unsigned int *link_id,
        os_macaddr_t *link_addr,
        os_macaddr_t *link_bssid)
{
    struct nlattr *tb[MTK_NL80211_VENDOR_ATTR_CONNECTED_STA_MLD_MAX + 1];
    const int err = nla_parse_nested(tb, ARRAY_SIZE(tb) - 1, sta, NULL);
    if (err) return false;

    struct nlattr *id = tb[MTK_NL80211_VENDOR_ATTR_CONNECTED_STA_MLD_AFFILIATED_STA_LINKID];
    struct nlattr *mac = tb[MTK_NL80211_VENDOR_ATTR_CONNECTED_STA_MLD_AFFILIATED_STA_MAC];
    struct nlattr *bssid = tb[MTK_NL80211_VENDOR_ATTR_CONNECTED_STA_MLD_AFFILIATED_STA_BSSID];
    if (id == NULL) return false;
    if (mac == NULL) return false;
    if (bssid == NULL) return false;
    if (WARN_ON(nla_len(id) != sizeof(uint8_t))) return false;
    if (WARN_ON(nla_len(mac) != sizeof(link_addr->addr))) return false;
    if (WARN_ON(nla_len(bssid) != sizeof(link_bssid->addr))) return false;
    if (link_id != NULL) *link_id = nla_get_u8(id);
    if (link_addr != NULL) memcpy(link_addr->addr, nla_data(mac), nla_len(mac));
    if (link_bssid != NULL) memcpy(link_bssid->addr, nla_data(bssid), nla_len(bssid));

    return true;
}

struct nl_msg *mtk_vendor_cmd_get_assoc_req_frm_msg(const int family_id, const int ifindex, const os_macaddr_t *mac)
{
    if (family_id < 0) return NULL;
    if (ifindex == 0) return NULL;

    const int subcmd = MTK_NL80211_VENDOR_SUBCMD_EASYMESH;
    struct nl_msg *msg = mtk_vendor_cmd_msg(family_id, subcmd, ifindex);
    if (WARN_ON(msg == NULL)) return NULL;
    int err = 0;

    {
        void *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
        const size_t len = sizeof(mac->addr);
        err |= nla_put(msg, MTK_NL80211_VENDOR_ATTR_EASYMESH_GET_ASSOC_REQ_FRAME, len, mac->addr);
        err |= nla_nest_end(msg, data);
    }

    if (err)
    {
        nlmsg_free(msg);
        msg = NULL;
    }

    return msg;
}

bool mtk_vendor_cmd_get_assoc_req_frm_parse(struct nl_msg *resp, void **data, uint32_t *len)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    int err = 0;

    err = genlmsg_parse(nlmsg_hdr(resp), 0, tb, ARRAY_SIZE(tb) - 1, NULL);
    if (err) return false;

    struct nlattr *vendor_data = tb[NL80211_ATTR_VENDOR_DATA];
    if (vendor_data == NULL) return false;

    struct nlattr *vendor_tb[MTK_NL80211_VENDOR_ATTR_EASYMESH_MAX + 1];
    err = nla_parse_nested(vendor_tb, ARRAY_SIZE(vendor_tb) - 1, vendor_data, NULL);
    if (err) return false;

    struct nlattr *frame = vendor_tb[MTK_NL80211_VENDOR_ATTR_EASYMESH_GET_ASSOC_REQ_FRAME];
    if (frame == NULL) return false;

    if (data != NULL) *data = nla_data(frame);
    if (len != NULL) *len = nla_len(frame);

    return true;
}

struct nl_msg *mtk_vendor_cmd_get_cac_capability(const int family_id, const int ifindex)
{
    if (family_id < 0) return NULL;
    if (ifindex == 0) return NULL;

    const int subcmd = MTK_NL80211_VENDOR_SUBCMD_GET_CAP;
    struct nl_msg *msg = mtk_vendor_cmd_msg(family_id, subcmd, ifindex);
    if (WARN_ON(msg == NULL)) return NULL;
    int err = 0;
    {
        void *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
        err |= nla_put_u16(msg, MTK_NL80211_VENDOR_ATTR_GET_CAP_INFO_CAC_CAP, 0);
        err |= nla_nest_end(msg, data);
    }
    if (err)
    {
        nlmsg_free(msg);
        msg = NULL;
    }
    return msg;
}

bool mtk_vendor_cmd_get_cac_capability_parse(struct nl_msg *resp, void **data, uint32_t *len)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    int err = 0;

    err = genlmsg_parse(nlmsg_hdr(resp), 0, tb, ARRAY_SIZE(tb) - 1, NULL);
    if (err) return false;

    struct nlattr *vendor_data = tb[NL80211_ATTR_VENDOR_DATA];
    if (vendor_data == NULL) return false;

    struct nlattr *vendor_tb[MTK_NL80211_VENDOR_ATTR_GET_CAP_INFO_MAX + 1];
    err = nla_parse_nested(vendor_tb, ARRAY_SIZE(vendor_tb) - 1, vendor_data, NULL);
    if (err) return false;

    struct nlattr *frame = vendor_tb[MTK_NL80211_VENDOR_ATTR_GET_CAP_INFO_CAC_CAP];
    if (frame == NULL) return false;

    if (data != NULL) *data = nla_data(frame);
    if (len != NULL) *len = nla_len(frame);

    return true;
}
