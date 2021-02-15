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

#define _GNU_SOURCE
#include "nl80211.h"
#include "stats_nl80211.h"
#include <string.h>

#include <ev.h>
#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

bool nl80211_stats_clients_get(radio_entry_t *radio_cfg, radio_essid_t *essid,
                               target_stats_clients_cb_t *client_cb,
                               ds_dlist_t *client_list, void *client_ctx)
{
//    ds_dlist_t working_list = DS_DLIST_INIT(ds_dlist_t, od_cof);
    ds_dlist_t working_list = DS_DLIST_INIT(target_client_record_t, node);
    ds_dlist_t ssid_list = DS_DLIST_INIT(ssid_list_t, node);
    target_client_record_t *cl;
    ssid_list_t *ssid = NULL;
    struct nl_call_param nl_call_param = {
        .ifname = radio_cfg->if_name,
        .type = radio_cfg->type,
        .list = &working_list,
    //  .list = client_list,
    };
    struct nl_call_param ssid_call_param = {
        .ifname = radio_cfg->if_name,
        .type = radio_cfg->type,
        .list = &ssid_list,
    };
    bool ret = true;

    if (nl80211_get_ssid(&ssid_call_param) < 0)
        ret = false;

    while (!ds_dlist_is_empty(&ssid_list)) {
        ssid = ds_dlist_head(&ssid_list);

        nl_call_param.ifname  = ssid->ifname;
        //nl_call_param.list = &working_list;

        if (nl80211_get_assoclist(&nl_call_param) < 0) {
            ds_dlist_remove(&ssid_list,ssid);
            continue;
        }
        LOGD("%s: assoc returned %d, list %d", ssid->ifname, ret, ds_dlist_is_empty(&working_list));

        while (!ds_dlist_is_empty(&working_list)) {
            cl = ds_dlist_head(&working_list);
            strncpy(cl->info.essid, ssid->ssid, sizeof(cl->info.essid));
            ds_dlist_remove(&working_list, cl);
            ds_dlist_insert_tail(client_list, cl);
        }
        ds_dlist_remove(&ssid_list,ssid);
        free(ssid);
    }

    (*client_cb)(client_list, client_ctx, ret);
    return ret;
}

bool nl80211_client_stats_convert(radio_entry_t *radio_cfg, target_client_record_t *data_new,
                                  target_client_record_t *data_old, dpp_client_record_t *client_record)
{
    memcpy(client_record->info.mac, data_new->info.mac, sizeof(data_new->info.mac));
    memcpy(client_record->info.essid, data_new->info.essid, sizeof(radio_cfg->if_name));

    client_record->stats.rssi       = data_new->stats.rssi;
    client_record->stats.rate_tx    = data_new->stats.rate_tx;
    client_record->stats.rate_rx    = data_new->stats.rate_rx;
    client_record->stats.bytes_tx   = data_new->stats.bytes_tx   - data_old->stats.bytes_tx;
    client_record->stats.bytes_rx   = data_new->stats.bytes_rx   - data_old->stats.bytes_rx;
    client_record->stats.frames_tx  = data_new->stats.frames_tx  - data_old->stats.frames_tx;
    client_record->stats.frames_rx  = data_new->stats.frames_rx  - data_old->stats.frames_rx;
    client_record->stats.retries_tx = data_new->stats.retries_tx - data_old->stats.retries_tx;
    client_record->stats.errors_tx  = data_new->stats.errors_tx  - data_old->stats.errors_tx;
    client_record->stats.errors_rx  = data_new->stats.errors_rx  - data_old->stats.errors_rx;

    LOGT("Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
         "bytes_tx=%llu",
         radio_get_name_from_type(radio_cfg->type),
         MAC_ADDRESS_PRINT(data_new->info.mac),
         client_record->stats.bytes_tx);
    /* TODO: To check if txrate and rxrate needs recalculation due to driver bugs */

    return true;
}

bool nl80211_stats_survey_get(radio_entry_t *radio_cfg, uint32_t *chan_list,
                              uint32_t chan_num, radio_scan_type_t scan_type,
                              target_stats_survey_cb_t *survey_cb,
                              ds_dlist_t *survey_list, void *survey_ctx)
{
    ds_dlist_t raw_survey_list = DS_DLIST_INIT(target_survey_record_t, node);
    target_survey_record_t *survey;
    struct nl_call_param nl_call_param = {
        .ifname = radio_cfg->if_name,
        .type = radio_cfg->type,
        .list = &raw_survey_list,
    };
    bool ret = true;

    if (nl80211_get_survey(&nl_call_param) < 0)
        ret = false;

    LOGT("%s: survey returned %d, list %d", radio_cfg->if_name, ret, ds_dlist_is_empty(&raw_survey_list));
    while (!ds_dlist_is_empty(&raw_survey_list)) {
        survey = ds_dlist_head(&raw_survey_list);
        ds_dlist_remove(&raw_survey_list, survey);

        if ((scan_type == RADIO_SCAN_TYPE_ONCHAN) && (survey->info.chan == chan_list[0])) {
            LOGT("Fetched %s %s %u survey "
            "{active=%u busy=%u tx=%u rx=%u dur=%u}",
            radio_get_name_from_type(radio_cfg->type),
            radio_get_scan_name_from_type(scan_type),
            survey->info.chan,
            survey->chan_active,
            survey->chan_busy,
            survey->chan_tx,
            survey->chan_rx,
            survey->duration_ms);
            ds_dlist_insert_tail(survey_list, survey);
        } else if ((scan_type != RADIO_SCAN_TYPE_ONCHAN) && (survey->duration_ms != 0)) {
            LOGT("Fetched %s %s %u survey "
            "{active=%u busy=%u tx=%u rx=%u dur=%u}",
            radio_get_name_from_type(radio_cfg->type),
            radio_get_scan_name_from_type(scan_type),
            survey->info.chan,
            survey->chan_active,
            survey->chan_busy,
            survey->chan_tx,
            survey->chan_rx,
            survey->duration_ms);
            ds_dlist_insert_tail(survey_list, survey);
        } else {
            target_survey_record_free(survey);
            survey = NULL;
        }
    }
    (*survey_cb)(survey_list, survey_ctx, ret);

    return ret;
}

bool nl80211_stats_survey_convert(radio_entry_t *radio_cfg, radio_scan_type_t scan_type,
                                  target_survey_record_t *data_new, target_survey_record_t *data_old,
                                  dpp_survey_record_t *survey_record)
{
    /* TODO: Review if % needs to be calculated on delta stats or on data_new directly */
    survey_record->info.chan     = data_new->info.chan;
    survey_record->chan_tx       = PERCENT(data_new->chan_tx, data_new->duration_ms);
    survey_record->chan_self     = PERCENT(data_new->chan_self, data_new->duration_ms);
    survey_record->chan_rx       = PERCENT(data_new->chan_rx, data_new->duration_ms);
    survey_record->chan_busy_ext = PERCENT(data_new->chan_busy_ext, data_new->duration_ms);
    survey_record->chan_busy     = PERCENT(data_new->chan_busy, data_new->duration_ms);
//  survey_record->chan_noise    = data_new->chan_noise;
    survey_record->duration_ms   = data_new->duration_ms;
    LOGT("Processed %s %s %u survey delta "
        "{active=%u busy=%u tx=%u self=%u rx=%u ext=%u}",
        radio_get_name_from_type(radio_cfg->type),
        radio_get_scan_name_from_type(scan_type),
        survey_record->info.chan,
        survey_record->chan_active,
        survey_record->chan_busy,
        survey_record->chan_tx,
        survey_record->chan_self,
        survey_record->chan_rx,
        survey_record->chan_busy_ext);

    return true;
}

bool nl80211_stats_scan_start(radio_entry_t *radio_cfg, uint32_t *chan_list, uint32_t chan_num,
                              radio_scan_type_t scan_type, int32_t dwell_time,
                              target_scan_cb_t *scan_cb, void *scan_ctx)
{
    char *ifname = radio_cfg->if_name;
    bool ret = true;

    if (nl80211_scan_trigger(ifname, chan_list, chan_num, dwell_time, scan_type, scan_cb, scan_ctx) < 0)
        ret = false;
    LOGT("%s: scan trigger returned %d", radio_cfg->if_name, ret);

    if (ret == false) {
        LOG(ERR, "%s: failed to trigger scan, aborting", radio_cfg->if_name);
        (*scan_cb)(scan_ctx, ret);
    }
    return true;
}

bool nl80211_stats_scan_stop(radio_entry_t *radio_cfg, radio_scan_type_t scan_type)
{
    char *ifname = radio_cfg->if_name;
    bool ret = true;

    if (nl80211_scan_abort(ifname) < 0)
        ret = false;

    LOGT("%s: scan abort returned %d", radio_cfg->if_name, ret);

    return true;
}

bool nl80211_stats_scan_get(radio_entry_t *radio_cfg, uint32_t *chan_list, uint32_t chan_num,
                            radio_scan_type_t scan_type, dpp_neighbor_report_data_t *scan_results)
{
    struct nl_call_param nl_call_param = {
        .ifname = radio_cfg->if_name,
        .type = radio_cfg->type,
        .list = &scan_results->list,
    };
    bool ret = true;

    if (nl80211_scan_dump(&nl_call_param) < 0)
        ret = false;

    LOGT("Parsed %s %s scan results for channel %d",
         radio_get_name_from_type(radio_cfg->type),
         radio_get_scan_name_from_type(scan_type),
         chan_list[0]);
    return ret;
}

static __attribute__((constructor)) void sm_init(void)
{
    sm_stats_nl80211_init();
}
