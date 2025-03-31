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
#include <cr.h>
#include <cr_goto.h>
#include <cr_nl_cmd.h>
#include <log.h>
#include <memutil.h>
#include <os.h>
#include <os_types.h>

#include <net/if.h>

#include <mtk_family_id.h>
#include <mtk_sta_mld_info.h>
#include <mtk_vendor_cmd.h>

struct mtk_sta_mld_info_fetcher
{
    cr_state_t state;
    cr_context_t *ctx;
    cr_nl_cmd_t *family_id;
    cr_nl_cmd_t *sta_mld;

    bool ok;
    int ifindex;
    struct mtk_sta_mld_info info;

    char *vif_name;
    unsigned int group_id;
    os_macaddr_t link_addr;
};

mtk_sta_mld_info_fetcher_t *mtk_sta_mld_info_fetcher(
        cr_context_t *ctx,
        const char *vif_name,
        const unsigned int group_id,
        const os_macaddr_t *link_addr)
{
    if (WARN_ON(vif_name == NULL)) return NULL;
    mtk_sta_mld_info_fetcher_t *f = CALLOC(1, sizeof(*f));
    f->ctx = ctx;
    f->link_addr = *link_addr;
    f->group_id = group_id;
    f->vif_name = STRDUP(vif_name);
    return f;
}

static bool mtk_sta_mld_info_fetcher_parse(mtk_sta_mld_info_fetcher_t *f)
{
    if (f == NULL) return false;
    if (cr_nl_cmd_is_ok(f->sta_mld) == false) return false;

    struct nl_msg **resp = cr_nl_cmd_resps(f->sta_mld);
    while (resp && *resp)
    {
        MEMZERO(f->info);

        struct nlattr *stas = NULL;
        mtk_vendor_cmd_get_sta_mld_parse(*resp, &f->info.group_id, &f->info.mld_addr, &stas);

        if (stas)
        {
            int rem;
            size_t link = 0;
            struct nlattr *sta;
            nla_for_each_nested(sta, stas, rem)
            {
                if (WARN_ON(link >= ARRAY_SIZE(f->info.links))) break;

                f->info.links[link].valid = mtk_vendor_cmd_get_sta_mld_parse_sta(
                        sta,
                        &f->info.links[link].link_id,
                        &f->info.links[link].link_addr,
                        &f->info.links[link].link_bssid);
                link++;
            }
        }

        resp++;

        size_t i;
        for (i = 0; i < ARRAY_SIZE(f->info.links); i++)
        {
            if (f->info.links[i].valid)
            {
                const size_t len = sizeof(f->link_addr.addr);
                if (memcmp(f->info.links[i].link_addr.addr, f->link_addr.addr, len) == 0)
                {
                    break;
                }
            }
        }
        const bool found = (i < ARRAY_SIZE(f->info.links));
        if (found) return true;
    }

    return false;
}

bool mtk_sta_mld_info_fetcher_run(mtk_sta_mld_info_fetcher_t *f)
{
    if (f == NULL) return true;
    CR_BEGIN(&f->state);
    f->ifindex = if_nametoindex(f->vif_name);

    f->family_id = cr_nl_cmd(NULL, NETLINK_GENERIC, mtk_family_id_msg());
    while (cr_nl_cmd_run(f->family_id) == false)
    {
        CR_YIELD(&f->state);
    }

    f->sta_mld = cr_nl_cmd(
            f->ctx,
            NETLINK_GENERIC,
            mtk_vendor_cmd_get_sta_mld_msg(mtk_family_id_parse(cr_nl_cmd_resp(f->family_id)), f->ifindex, f->group_id));
    while (cr_nl_cmd_run(f->sta_mld) == false)
    {
        CR_YIELD(&f->state);
    }

    f->ok = mtk_sta_mld_info_fetcher_parse(f);
    CR_END(&f->state);
}

const struct mtk_sta_mld_info *mtk_sta_mld_info_fetcher_get(const mtk_sta_mld_info_fetcher_t *f)
{
    if (f == NULL) return NULL;
    if (f->ok == false) return NULL;
    return &f->info;
}

void mtk_sta_mld_info_fetcher_drop(mtk_sta_mld_info_fetcher_t **f)
{
    if (*f == NULL) return;
    cr_nl_cmd_drop(&(*f)->sta_mld);
    cr_nl_cmd_drop(&(*f)->family_id);
    FREE((*f)->vif_name);
    FREE(*f);
    *f = NULL;
}

const struct mtk_sta_mld_info_link *mtk_sta_mld_info_fetcher_lookup_link_by_link_addr(
        const struct mtk_sta_mld_info *info,
        const os_macaddr_t *link_addr)
{
    if (info == NULL) return NULL;
    if (link_addr == NULL) return NULL;

    size_t i;
    for (i = 0; i < ARRAY_SIZE(info->links); i++)
    {
        if (info->links[i].valid)
        {
            const size_t len = sizeof(link_addr->addr);
            if (memcmp(link_addr->addr, info->links[i].link_addr.addr, len) == 0)
            {
                return &info->links[i];
            }
        }
    }
    return NULL;
}
