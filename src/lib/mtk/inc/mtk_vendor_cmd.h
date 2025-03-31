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

#ifndef MTK_VENDOR_CMD_H_INCLUDED
#define MTK_VENDOR_CMD_H_INCLUDED

#include <netlink/attr.h>
#include <netlink/msg.h>
#include <os_types.h>

struct nl_msg *mtk_vendor_cmd_msg(const int family_id, const int subcmd_id, const int ifindex);

struct nl_msg *mtk_vendor_cmd_get_ap_mld_msg(const int family_id, const int ifindex, const os_macaddr_t *mac);

bool mtk_vendor_cmd_get_ap_mld_parse(
        struct nl_msg *resp,
        unsigned int *group_id,
        os_macaddr_t *mld_addr,
        struct nlattr **aps_attr);

bool mtk_vendor_cmd_get_ap_mld_parse_ap(struct nlattr *ap, unsigned int *link_id, os_macaddr_t *link_addr);

struct nl_msg *mtk_vendor_cmd_get_sta_mld_msg(const int family_id, const int ifindex, const int mld_group_id);

bool mtk_vendor_cmd_get_sta_mld_parse(
        struct nl_msg *resp,
        unsigned int *group_id,
        os_macaddr_t *mld_addr,
        struct nlattr **stas_attr);

bool mtk_vendor_cmd_get_sta_mld_parse_sta(
        struct nlattr *sta,
        unsigned int *link_id,
        os_macaddr_t *link_addr,
        os_macaddr_t *link_bssid);

struct nl_msg *mtk_vendor_cmd_get_assoc_req_frm_msg(const int family_id, const int ifindex, const os_macaddr_t *mac);

bool mtk_vendor_cmd_get_assoc_req_frm_parse(struct nl_msg *msg, void **data, uint32_t *len);

struct nl_msg *mtk_vendor_cmd_get_cac_capability(const int family_id, const int ifindex);

bool mtk_vendor_cmd_get_cac_capability_parse(struct nl_msg *msg, void **data, uint32_t *len);

#endif /* MTK_VENDOR_CMD_H_INCLUDED */
