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

#ifndef NL80211_SCAN_H_INCLUDED
#define NL80211_SCAN_H_INCLUDED

#include "ds_tree.h"
#include <net/if.h>
#include "dpp_neighbor.h"

typedef bool target_scan_cb_t(
        void *scan_ctx,
        int   status);

struct nl80211_scan {
    char name[IFNAMSIZ];
    target_scan_cb_t *scan_cb;
    void *scan_ctx;
    ds_tree_node_t if_node;
    ev_async async;
};

bool nl80211_stats_scan_start(
        radio_entry_t *radio_cfg,
        uint32_t *chan_list,
        uint32_t chan_num,
        radio_scan_type_t scan_type,
        int32_t dwell_time,
        target_scan_cb_t *scan_cb,
        void *scan_ctx
);

bool nl80211_stats_scan_stop(
        radio_entry_t *radio_cfg,
        radio_scan_type_t scan_type
);

bool nl80211_stats_scan_get(
        radio_entry_t *radio_cfg,
        uint32_t *chan_list,
        uint32_t chan_num,
        radio_scan_type_t scan_type,
        dpp_neighbor_report_data_t *scan_results
);

void nl80211_scan_finish(char *name, bool state);

#endif /* NL80211_SCAN_H_INCLUDED */
