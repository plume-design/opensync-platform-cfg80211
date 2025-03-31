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

#ifndef MTK_ASSOC_REQ_FRM_H_INCLUDED
#define MTK_ASSOC_REQ_FRM_H_INCLUDED

#include <cr.h>
#include <os_types.h>
#include <stdbool.h>

typedef struct mtk_assoc_req_frm_fetcher mtk_assoc_req_frm_fetcher_t;

mtk_assoc_req_frm_fetcher_t *mtk_assoc_req_frm_fetcher(
        cr_context_t *ctx,
        const char *vif_name,
        const os_macaddr_t *link_addr);
bool mtk_assoc_req_frm_fetcher_run(mtk_assoc_req_frm_fetcher_t *info);
void mtk_assoc_req_frm_fetcher_drop(mtk_assoc_req_frm_fetcher_t **info);
const void *mtk_assoc_req_frm_fetcher_data(const mtk_assoc_req_frm_fetcher_t *info);
size_t mtk_assoc_req_frm_fetcher_len(const mtk_assoc_req_frm_fetcher_t *info);

#endif /* MTK_ASSOC_REQ_FRM_H_INCLUDED */
