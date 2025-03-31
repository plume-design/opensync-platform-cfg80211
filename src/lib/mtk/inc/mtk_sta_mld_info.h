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

#ifndef MTK_STA_MLD_INFO_H_INCLUDED
#define MTK_STA_MLD_INFO_H_INCLUDED

#include <cr.h>
#include <os_types.h>
#include <stdbool.h>

struct mtk_sta_mld_info_link
{
    bool valid;
    unsigned int link_id;
    os_macaddr_t link_addr;
    os_macaddr_t link_bssid;
};

struct mtk_sta_mld_info
{
    unsigned int group_id;
    os_macaddr_t mld_addr;
    struct mtk_sta_mld_info_link links[16];
};

typedef struct mtk_sta_mld_info_fetcher mtk_sta_mld_info_fetcher_t;

mtk_sta_mld_info_fetcher_t *mtk_sta_mld_info_fetcher(
        cr_context_t *ctx,
        const char *vif_name,
        const unsigned int group_id,
        const os_macaddr_t *link_addr);
bool mtk_sta_mld_info_fetcher_run(mtk_sta_mld_info_fetcher_t *info);
void mtk_sta_mld_info_fetcher_drop(mtk_sta_mld_info_fetcher_t **info);
const struct mtk_sta_mld_info *mtk_sta_mld_info_fetcher_get(const mtk_sta_mld_info_fetcher_t *info);
const struct mtk_sta_mld_info_link *mtk_sta_mld_info_fetcher_lookup_link_by_link_addr(
        const struct mtk_sta_mld_info *info,
        const os_macaddr_t *link_addr);

#endif /* MTK_STA_MLD_INFO_H_INCLUDED */
