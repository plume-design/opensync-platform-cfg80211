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

#include "mtk_vendor_nl80211_copy.h"
#include <mtk_dfs_cac_req_frm.h>
#include <mtk_family_id.h>
#include <mtk_vendor_cmd.h>

#define MAX_CAC_CHLIST_NUM 16
#define MAX_CAC_OPCAP_NUM 16

struct GNU_PACKED cac_opcap
{
    unsigned char op_class;
    unsigned char ch_num;
    unsigned char ch_list[MAX_CAC_CHLIST_NUM];
    unsigned short cac_time[MAX_CAC_CHLIST_NUM];
    unsigned int last_cac_time[MAX_CAC_CHLIST_NUM];
    unsigned short non_occupancy_remain[MAX_CAC_CHLIST_NUM];
};

struct GNU_PACKED cac_capability
{
    unsigned char country_code[2];
    unsigned char rdd_region;
    unsigned char op_class_num;
    struct cac_opcap opcap[16];
    unsigned char active_cac;
    unsigned char ch_num;
    unsigned int remain_time;
    unsigned char cac_mode;
    unsigned char dedicated_cac_enabled;
    unsigned char dedicated_cac_active;
    unsigned char dedicated_ch_num;
    unsigned char dedicated_bw;
    unsigned int dedicated_remain_time;
};

struct mtk_dfs_cac_req_frm_fetcher
{
    cr_state_t state;
    cr_context_t *ctx;
    cr_nl_cmd_t *family_id;
    cr_nl_cmd_t *cac_req;

    bool ok;
    int ifindex;
    void *data;
    uint32_t len;

    char *vif_name;
    struct cac_capability *cac;
};

mtk_dfs_cac_req_frm_fetcher_t *mtk_dfs_cac_req_frm_fetcher(cr_context_t *ctx, const char *vif_name)
{
    if (WARN_ON(vif_name == NULL)) return NULL;
    mtk_dfs_cac_req_frm_fetcher_t *f = CALLOC(1, sizeof(*f));
    f->ctx = ctx;
    f->vif_name = STRDUP(vif_name);
    return f;
}

static bool mtk_dfs_cac_req_frm_fetcher_parse(mtk_dfs_cac_req_frm_fetcher_t *f)
{
    if (f == NULL) return false;
    if (cr_nl_cmd_is_ok(f->cac_req) == false) return false;

    struct nl_msg **resp = cr_nl_cmd_resps(f->cac_req);
    while (resp && *resp)
    {
        f->data = NULL;
        f->len = 0;
        f->cac = NULL;

        if (mtk_vendor_cmd_get_cac_capability_parse(*resp, &f->data, &f->len))
        {
            f->cac = f->data;
            return true;
        }

        resp++;
    }
    return false;
}

bool mtk_dfs_cac_req_frm_fetcher_run(mtk_dfs_cac_req_frm_fetcher_t *f)
{
    if (f == NULL) return true;
    CR_BEGIN(&f->state);
    f->ifindex = if_nametoindex(f->vif_name);

    f->family_id = cr_nl_cmd(NULL, NETLINK_GENERIC, mtk_family_id_msg());
    while (cr_nl_cmd_run(f->family_id) == false)
    {
        CR_YIELD(&f->state);
    }

    f->cac_req = cr_nl_cmd(
            f->ctx,
            NETLINK_GENERIC,
            mtk_vendor_cmd_get_cac_capability(mtk_family_id_parse(cr_nl_cmd_resp(f->family_id)), f->ifindex));
    while (cr_nl_cmd_run(f->cac_req) == false)
    {
        CR_YIELD(&f->state);
    }

    f->ok = mtk_dfs_cac_req_frm_fetcher_parse(f);
    CR_END(&f->state);
}

int mtk_dfs_cac_req_frm_fetcher_ch_num(const mtk_dfs_cac_req_frm_fetcher_t *f)
{
    if (f == NULL) return -1;
    if (f->ok == false) return -1;
    return (int)f->cac->ch_num;
}
int mtk_dfs_cac_req_frm_fetcher_cac_active(const mtk_dfs_cac_req_frm_fetcher_t *f)
{
    if (f == NULL) return -1;
    if (f->ok == false) return -1;
    return (int)f->cac->active_cac;
}

size_t mtk_dfs_cac_req_frm_fetcher_len(const mtk_dfs_cac_req_frm_fetcher_t *f)
{
    if (f == NULL) return 0;
    if (f->ok == false) return 0;
    return f->len;
}

void mtk_dfs_cac_req_frm_fetcher_drop(mtk_dfs_cac_req_frm_fetcher_t **f)
{
    if (*f == NULL) return;
    cr_nl_cmd_drop(&(*f)->cac_req);
    cr_nl_cmd_drop(&(*f)->family_id);
    FREE((*f)->vif_name);
    FREE(*f);
    *f = NULL;
}
