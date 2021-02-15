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

#ifndef TARGET_NETLINK_H_INCLUDED
#define TARGET_NETLINK_H_INCLUDED

extern struct ev_loop *target_mainloop;
extern bool nl80211_client_stats_convert(radio_entry_t *, target_client_record_t *, target_client_record_t *, dpp_client_record_t *);
extern bool nl80211_stats_clients_get(radio_entry_t *, radio_essid_t *, target_stats_clients_cb_t *, ds_dlist_t *, void *);
extern bool nl80211_stats_survey_get(radio_entry_t *, uint32_t *, uint32_t, radio_scan_type_t, target_stats_survey_cb_t *,
                             ds_dlist_t *, void *survey_ctx);
extern bool nl80211_stats_survey_convert(radio_entry_t *, radio_scan_type_t,
                                 target_survey_record_t *, target_survey_record_t *,
                                 dpp_survey_record_t *);
extern bool nl80211_stats_scan_start(radio_entry_t *, uint32_t *, uint32_t, radio_scan_type_t, int32_t,
                                     target_scan_cb_t *, void *);
extern bool nl80211_stats_scan_stop(radio_entry_t *, radio_scan_type_t);
extern bool nl80211_stats_scan_get(radio_entry_t *, uint32_t *, uint32_t,
                           radio_scan_type_t, dpp_neighbor_report_data_t *);

#endif /* TARGET_NETLINK_H_INCLUDED */
