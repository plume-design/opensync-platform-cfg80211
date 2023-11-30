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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/socket.h>

#include "log.h"
#include "os.h"
#include "os_nif.h"
#include "os_regex.h"
#include "os_types.h"
#include "os_util.h"
#include "target.h"
#include "util.h"

#include "nl80211.h"
#include "target_nl80211.h"

#include "nl80211_stats.h"
#include "nl80211_client.h"
#include "nl80211_survey.h"
#include "nl80211_scan.h"
#include "nl80211_device.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

/******************************************************************************
 *  INTERFACE definitions
 *****************************************************************************/

static bool
check_interface_exists(char *if_name)
{
    struct dirent *i;
    DIR *d;

    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        return false;

    while ((i = readdir(d)))
        if (strcmp(i->d_name, if_name) == 0) {
            closedir(d);
            return true;
        }

    closedir(d);
    return false;
}


static bool
check_radio_exists(char *phy_name)
{
    struct dirent *i;
    DIR *d;

    if (WARN_ON(!(d = opendir(CONFIG_MAC80211_WIPHY_PATH))))
        return false;

    while ((i = readdir(d)))
        if (strcmp(i->d_name, phy_name) == 0) {
            closedir(d);
            return true;
        }

    closedir(d);
    return false;
}


bool target_is_radio_interface_ready(char *phy_name)
{
    bool rc;
    rc = check_radio_exists(phy_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}

bool target_is_interface_ready(char *if_name)
{
    bool rc;
    rc = check_interface_exists(if_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}


/******************************************************************************
 *  STATS definitions
 *****************************************************************************/

bool target_radio_tx_stats_enable(radio_entry_t *radio_cfg, bool enable)
{
    return true;
}

bool target_radio_fast_scan_enable(radio_entry_t *radio_cfg, ifname_t if_name)
{
    return true;
}


/******************************************************************************
 *  CLIENT definitions
 *****************************************************************************/

void target_client_record_free(target_client_record_t *record)
{
    if (NULL != record)
        free(record);
}

bool target_stats_clients_get(radio_entry_t *radio_cfg,
                              radio_essid_t *essid,
                              target_stats_clients_cb_t *client_cb,
                              ds_dlist_t *client_list,
                              void *client_ctx)
{
    bool ret;

    ret = nl80211_stats_clients_get(radio_cfg,
                                    essid,
                                    client_list,
                                    client_ctx);

    (*client_cb)(client_list, client_ctx, ret);
    return ret;
}

bool target_stats_clients_convert(radio_entry_t *radio_cfg,
                                  target_client_record_t *data_new,
                                  target_client_record_t *data_old,
                                  dpp_client_record_t *client_record)
{
    return nl80211_client_stats_convert(radio_cfg,
                                        data_new,
                                        data_old,
                                        client_record);
}


/******************************************************************************
 *  SURVEY definitions
 *****************************************************************************/

target_survey_record_t *target_survey_record_alloc()
{
    target_survey_record_t *record = NULL;

    record = malloc(sizeof(target_survey_record_t));
    if (record == NULL)
        return NULL;

    memset(record, 0, sizeof(target_survey_record_t));

    return record;
}

void target_survey_record_free(target_survey_record_t *record)
{
    if (NULL != record)
        free(record);
}

bool target_stats_survey_get(radio_entry_t *radio_cfg,
                             uint32_t *chan_list,
                             uint32_t chan_num,
                             radio_scan_type_t scan_type,
                             target_stats_survey_cb_t *survey_cb,
                             ds_dlist_t *survey_list,
                             void *survey_ctx)
{
    bool ret;

    ret = nl80211_stats_survey_get(radio_cfg,
                                   chan_list,
                                   chan_num,
                                   scan_type,
                                   survey_list,
                                   survey_ctx);

    (*survey_cb)(survey_list, survey_ctx, ret);
    return ret;
}

bool target_stats_survey_convert(radio_entry_t *radio_cfg,
                                 radio_scan_type_t scan_type,
                                 target_survey_record_t *data_new,
                                 target_survey_record_t *data_old,
                                 dpp_survey_record_t *survey_record)
{
    return nl80211_stats_survey_convert(radio_cfg,
                                        scan_type,
                                        data_new,
                                        data_old,
                                        survey_record);
}


/******************************************************************************
 *  CAPACITY definitions
 *****************************************************************************/

bool target_stats_capacity_enable(radio_entry_t *radio_cfg, bool enabled)
{
    /* TODO: need to develop for MTK platform */
    return true;
}

bool target_stats_capacity_get(radio_entry_t *radio_cfg,
                               target_capacity_data_t *capacity_new)
{
    /* TODO: need to develop for MTK platform */
    return true;
}

bool target_stats_capacity_convert(target_capacity_data_t *capacity_new,
                                   target_capacity_data_t *capacity_old,
                                   dpp_capacity_record_t *capacity_entry)
{
    /* TODO: need to develop for MTK platform */
    return true;
}


/******************************************************************************
 *  NEIGHBORS definitions
 *****************************************************************************/

bool target_stats_scan_start(radio_entry_t *radio_cfg,
                             uint32_t *chan_list,
                             uint32_t chan_num,
                             radio_scan_type_t scan_type,
                             int32_t dwell_time,
                             target_scan_cb_t *scan_cb,
                             void *scan_ctx)
{
    return nl80211_stats_scan_start(radio_cfg,
                                    chan_list,
                                    chan_num,
                                    scan_type,
                                    dwell_time,
                                    scan_cb,
                                    scan_ctx);
}

bool target_stats_scan_stop(radio_entry_t *radio_cfg,
                            radio_scan_type_t scan_type)
{
    return nl80211_stats_scan_stop(radio_cfg, scan_type);
}

bool target_stats_scan_get(radio_entry_t *radio_cfg,
                           uint32_t *chan_list,
                           uint32_t chan_num,
                           radio_scan_type_t scan_type,
                           dpp_neighbor_report_data_t *scan_results)
{
    return nl80211_stats_scan_get(radio_cfg,
                                  chan_list,
                                  chan_num,
                                  scan_type,
                                  scan_results);
}

/******************************************************************************
 *  DEVICE definitions
 *****************************************************************************/

bool target_stats_device_temp_get(radio_entry_t *radio_cfg,
                                  dpp_device_temp_t *temp_entry)
{
    int32_t temperature;

    if ((temperature = util_get_temp_info(radio_cfg->phy_name)) < 0) {
        LOG(ERR, "%s: Failed to open temp input files", radio_cfg->phy_name);
        return false;
    }
    temp_entry->type  = radio_cfg->type;
    temp_entry->value = temperature / 1000;

    LOGI("%s: temperature %d", radio_cfg->phy_name, temp_entry->value);

    return true;
}

bool target_stats_device_txchainmask_get(
        radio_entry_t              *radio_cfg,
        dpp_device_txchainmask_t   *txchainmask_entry)
{
    txchainmask_entry->type = radio_cfg->type;

    if (nl80211_get_tx_chainmask(radio_cfg->phy_name, &txchainmask_entry->value) < 0) {
        LOGD("%s: Failed to get tx_chainmask value", radio_cfg->phy_name);
        return false;
    }

    LOGI("%s: tx_chainmask %d", radio_cfg->phy_name, txchainmask_entry->value);

    return true;
}
