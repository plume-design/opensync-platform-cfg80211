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
#include "nl80211_stats.h"
#include "target_nl80211.h"
#include <string.h>

#include <ev.h>
#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>
#include "kconfig.h"

static target_survey_record_t* target_survey_record_alloc()
{
    target_survey_record_t *record = NULL;

    record = malloc(sizeof(target_survey_record_t));
    if (record == NULL)
        return NULL;

    memset(record, 0, sizeof(target_survey_record_t));

    return record;
}

static int nl80211_survey_recv(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nl_call_param *nl_call_param = (struct nl_call_param *)arg;
    struct nlattr *si[NL80211_SURVEY_INFO_MAX + 1];
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    static struct nla_policy sp[NL80211_SURVEY_INFO_MAX + 1] = {
        [NL80211_SURVEY_INFO_FREQUENCY]         = { .type = NLA_U32 },
        [NL80211_SURVEY_INFO_TIME]              = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_TX]           = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_RX]           = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_BUSY]         = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_EXT_BUSY]     = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_SCAN]         = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_NOISE]             = { .type = NLA_U8 },
    };
    target_survey_record_t  *survey_record;
    memset(tb, 0, sizeof(tb));
    memset(si, 0, sizeof(si));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_SURVEY_INFO])
        return NL_OK;

    if (nla_parse_nested(si, NL80211_SURVEY_INFO_MAX,
                     tb[NL80211_ATTR_SURVEY_INFO], sp))
        return NL_SKIP;

    survey_record = target_survey_record_alloc();

    survey_record->info.timestamp_ms = get_timestamp();

    if (si[NL80211_SURVEY_INFO_FREQUENCY])
        survey_record->info.chan = util_freq_to_chan(
                                        nla_get_u32(si[NL80211_SURVEY_INFO_FREQUENCY]));

    if (si[NL80211_SURVEY_INFO_TIME_BSS_RX])
        survey_record->chan_self = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_BSS_RX]);

    if (si[NL80211_SURVEY_INFO_TIME_TX])
        survey_record->chan_tx = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_TX]);

    if (si[NL80211_SURVEY_INFO_TIME_RX])
        survey_record->chan_rx = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_RX]);

    if (si[NL80211_SURVEY_INFO_TIME_BUSY])
        survey_record->chan_busy = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_BUSY]);

    if (si[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
        survey_record->chan_busy_ext = nla_get_u64(si[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);

    if (si[NL80211_SURVEY_INFO_TIME])
        survey_record->duration_ms = nla_get_u64(si[NL80211_SURVEY_INFO_TIME]);

    if (si[NL80211_SURVEY_INFO_NOISE])
        survey_record->chan_noise = (int32_t)(int8_t)nla_get_u8(si[NL80211_SURVEY_INFO_NOISE]);

    if (survey_record->chan_noise == 0)
        survey_record->chan_noise = DEFAULT_NOISE_FLOOR;

    ds_dlist_insert_tail(nl_call_param->list, survey_record);

    return NL_OK;
}

int nl80211_get_survey(struct nl_global_info *nl_sm_global,
                            struct nl_call_param *nl_call_param)
{
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(nl_call_param->ifname)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_GET_SURVEY, true);
    if (!msg) {
        return -EINVAL;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nlmsg_send_and_recv(nl_sm_global, msg, nl80211_survey_recv, nl_call_param);
    return 0;
}

bool nl80211_stats_survey_get(radio_entry_t *radio_cfg, uint32_t *chan_list,
                              uint32_t chan_num, radio_scan_type_t scan_type,
                              ds_dlist_t *survey_list, void *survey_ctx)
{
    struct nl_global_info *nl_sm_global = get_nl_sm_global();
    ds_dlist_t raw_survey_list = DS_DLIST_INIT(target_survey_record_t, node);
    target_survey_record_t *survey;
    struct nl_call_param nl_call_param = {
        .ifname = radio_cfg->if_name,
        .type = radio_cfg->type,
        .list = &raw_survey_list,
    };
    bool ret = true;

    if (nl80211_get_survey(nl_sm_global, &nl_call_param) < 0)
        ret = false;

    LOGT("%s: survey returned %d, list %d", radio_cfg->if_name, ret, ds_dlist_is_empty(&raw_survey_list));
    while (!ds_dlist_is_empty(&raw_survey_list)) {
        survey = ds_dlist_head(&raw_survey_list);
        ds_dlist_remove(&raw_survey_list, survey);

        if ((scan_type == RADIO_SCAN_TYPE_ONCHAN) && (survey->info.chan == chan_list[0])) {
            LOGT("Fetched %s %s %u survey "
            "{active=%u busy=%u tx=%u rx=%u noise=%d dur=%u}",
            radio_get_name_from_type(radio_cfg->type),
            radio_get_scan_name_from_type(scan_type),
            survey->info.chan,
            survey->chan_active,
            survey->chan_busy,
            survey->chan_tx,
            survey->chan_rx,
            survey->chan_noise,
            survey->duration_ms);
            ds_dlist_insert_tail(survey_list, survey);
        } else if ((scan_type != RADIO_SCAN_TYPE_ONCHAN) && (survey->duration_ms != 0)) {
            LOGT("Fetched %s %s %u survey "
            "{active=%u busy=%u tx=%u rx=%u noise=%d dur=%u}",
            radio_get_name_from_type(radio_cfg->type),
            radio_get_scan_name_from_type(scan_type),
            survey->info.chan,
            survey->chan_active,
            survey->chan_busy,
            survey->chan_tx,
            survey->chan_rx,
            survey->chan_noise,
            survey->duration_ms);
            ds_dlist_insert_tail(survey_list, survey);
        } else {
            target_survey_record_free(survey);
            survey = NULL;
        }
    }

    return ret;
}

bool nl80211_stats_survey_check_offchan_scan(radio_entry_t *radio_cfg,
                                            target_survey_record_t *data_new,
                                            target_survey_record_t *data_old)
{
    if (!kconfig_enabled(CONFIG_PLATFORM_IS_MTK))
        return false;

    if (radio_cfg->chan == data_new->info.chan)
        return false;

    if (data_new->chan_tx != data_old->chan_tx)
        return true;

    if (data_new->chan_self != data_old->chan_self)
        return true;

    if (data_new->chan_rx != data_old->chan_rx)
        return true;

    if (data_new->chan_busy_ext != data_old->chan_busy_ext)
        return true;

    if (data_new->chan_busy != data_old->chan_busy)
        return true;

    if (data_new->duration_ms != data_old->duration_ms)
        return true;

    return false;
}

bool nl80211_stats_survey_convert(radio_entry_t *radio_cfg, radio_scan_type_t scan_type,
                                  target_survey_record_t *data_new, target_survey_record_t *data_old,
                                  dpp_survey_record_t *survey_record)
{
    target_survey_record_t data;

    // MTK offchan scan will reset register, so it doesn't calculate the delta value
    if (nl80211_stats_survey_check_offchan_scan(radio_cfg, data_new, data_old))
    {
        data.chan_tx       = data_new->chan_tx;
        data.chan_self     = data_new->chan_self;
        data.chan_rx       = data_new->chan_rx;
        data.chan_busy_ext = data_new->chan_busy_ext;
        data.chan_busy     = data_new->chan_busy;
        data.duration_ms  =  data_new->duration_ms;
        data.chan_noise    = data_new->chan_noise;
        data.chan_active   = data_new->chan_active;
    } else {
        data.chan_tx       = STATS_DELTA(data_new->chan_tx, data_old->chan_tx);
        data.chan_self     = STATS_DELTA(data_new->chan_self, data_old->chan_self);
        data.chan_rx       = STATS_DELTA(data_new->chan_rx, data_old->chan_rx);
        data.chan_busy_ext = STATS_DELTA(data_new->chan_busy_ext, data_old->chan_busy_ext);
        data.chan_busy     = STATS_DELTA(data_new->chan_busy, data_old->chan_busy);
        data.duration_ms  =  STATS_DELTA(data_new->duration_ms, data_old->duration_ms);
        data.chan_noise    = data_new->chan_noise;
        data.chan_active   = data_new->chan_active;
    }

    LOGT("Processed %s %s %u survey delta "
         "{active=%u busy=%u tx=%u self=%u rx=%u ext=%u noise=%d duration_ms =%u}",
         radio_get_name_from_type(radio_cfg->type),
         radio_get_scan_name_from_type(scan_type),
         data_new->info.chan,
         data.chan_active,
         data.chan_busy,
         data.chan_tx,
         data.chan_self,
         data.chan_rx,
         data.chan_busy_ext,
         data.chan_noise,
         data.duration_ms);

    survey_record->info.chan     = data_new->info.chan;
    survey_record->chan_tx       = PERCENT(data.chan_tx, data.duration_ms);
    survey_record->chan_self     = PERCENT(data.chan_self, data.duration_ms);
    survey_record->chan_rx       = PERCENT(data.chan_rx, data.duration_ms);
    survey_record->chan_busy_ext = PERCENT(data.chan_busy_ext, data.duration_ms);
    survey_record->chan_busy     = PERCENT(data.chan_busy, data.duration_ms);
    survey_record->chan_noise    = data.chan_noise;
    survey_record->duration_ms   = data.duration_ms;
    survey_record->chan_active   = data.chan_active;

    LOGT("Processed %s %s %u survey delta (percent) "
         "{active=%u busy=%u tx=%u self=%u rx=%u noise=%d ext=%u}",
         radio_get_name_from_type(radio_cfg->type),
         radio_get_scan_name_from_type(scan_type),
         survey_record->info.chan,
         survey_record->chan_active,
         survey_record->chan_busy,
         survey_record->chan_tx,
         survey_record->chan_self,
         survey_record->chan_rx,
         survey_record->chan_noise,
         survey_record->chan_busy_ext);

    return true;
}
