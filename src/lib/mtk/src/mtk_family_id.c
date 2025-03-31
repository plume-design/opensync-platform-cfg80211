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

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <mtk_family_id.h>

struct nl_msg *mtk_family_id_msg(void)
{
    const char *name = "nl80211";
    struct nl_msg *msg = nlmsg_alloc();
    if (WARN_ON(genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1) == NULL))
        goto free;
    if (WARN_ON(nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, name) < 0)) goto free;
    return msg;
free:
    nlmsg_free(msg);
    return NULL;
}

int mtk_family_id_parse(struct nl_msg *resp)
{
    if (resp == NULL) return -1;
    static struct nla_policy policy[CTRL_ATTR_MAX + 1] = {
        [CTRL_ATTR_FAMILY_ID] = {.type = NLA_U16},
    };
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct nlmsghdr *nlh = nlmsg_hdr(resp);
    const int parse_err = genlmsg_parse(nlh, 0, tb, CTRL_ATTR_MAX, policy);
    if (parse_err) return -1;
    struct nlattr *id = tb[CTRL_ATTR_FAMILY_ID];
    if (id != NULL) return nla_get_u16(id);
    return -1;
}
