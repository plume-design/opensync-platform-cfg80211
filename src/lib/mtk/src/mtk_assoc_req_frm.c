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

#include <mtk_assoc_req_frm.h>
#include <mtk_family_id.h>
#include <mtk_vendor_cmd.h>

struct mtk_assoc_req_frm_fetcher
{
    cr_state_t state;
    cr_context_t *ctx;
    cr_nl_cmd_t *family_id;
    cr_nl_cmd_t *assoc_req;

    bool ok;
    int ifindex;
    void *data;
    uint32_t len;

    char *vif_name;
    os_macaddr_t link_addr;
};

mtk_assoc_req_frm_fetcher_t *mtk_assoc_req_frm_fetcher(
        cr_context_t *ctx,
        const char *vif_name,
        const os_macaddr_t *link_addr)
{
    if (WARN_ON(vif_name == NULL)) return NULL;
    mtk_assoc_req_frm_fetcher_t *f = CALLOC(1, sizeof(*f));
    f->ctx = ctx;
    f->link_addr = *link_addr;
    f->vif_name = STRDUP(vif_name);
    return f;
}

static bool mtk_assoc_req_frm_fetcher_parse(mtk_assoc_req_frm_fetcher_t *f)
{
    if (f == NULL) return false;
    if (cr_nl_cmd_is_ok(f->assoc_req) == false) return false;

    struct nl_msg **resp = cr_nl_cmd_resps(f->assoc_req);
    while (resp && *resp)
    {
        f->data = NULL;
        f->len = 0;

        if (mtk_vendor_cmd_get_assoc_req_frm_parse(*resp, &f->data, &f->len))
        {
            return true;
        }

        resp++;
    }

    return false;
}

bool mtk_assoc_req_frm_fetcher_run(mtk_assoc_req_frm_fetcher_t *f)
{
    if (f == NULL) return true;
    CR_BEGIN(&f->state);
    f->ifindex = if_nametoindex(f->vif_name);

    f->family_id = cr_nl_cmd(NULL, NETLINK_GENERIC, mtk_family_id_msg());
    while (cr_nl_cmd_run(f->family_id) == false)
    {
        CR_YIELD(&f->state);
    }

    f->assoc_req = cr_nl_cmd(
            f->ctx,
            NETLINK_GENERIC,
            mtk_vendor_cmd_get_assoc_req_frm_msg(
                    mtk_family_id_parse(cr_nl_cmd_resp(f->family_id)),
                    f->ifindex,
                    &f->link_addr));
    while (cr_nl_cmd_run(f->assoc_req) == false)
    {
        CR_YIELD(&f->state);
    }

    f->ok = mtk_assoc_req_frm_fetcher_parse(f);
    CR_END(&f->state);
}

const void *mtk_assoc_req_frm_fetcher_data(const mtk_assoc_req_frm_fetcher_t *f)
{
    if (f == NULL) return NULL;
    if (f->ok == false) return NULL;
    return f->data;
}

size_t mtk_assoc_req_frm_fetcher_len(const mtk_assoc_req_frm_fetcher_t *f)
{
    if (f == NULL) return 0;
    if (f->ok == false) return 0;
    return f->len;
}

void mtk_assoc_req_frm_fetcher_drop(mtk_assoc_req_frm_fetcher_t **f)
{
    if (*f == NULL) return;
    cr_nl_cmd_drop(&(*f)->assoc_req);
    cr_nl_cmd_drop(&(*f)->family_id);
    FREE((*f)->vif_name);
    FREE(*f);
    *f = NULL;
}
