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

#ifndef STATS_NETLINK_H_INCLUDED
#define STATS_NETLINK_H_INCLUDED

#include "dpp_client.h"
#include "dpp_survey.h"


typedef struct {
    DPP_TARGET_CLIENT_RECORD_COMMON_STRUCT;
    dpp_client_stats_t  stats;
} target_client_record_t;

typedef struct
{
    DPP_TARGET_SURVEY_RECORD_COMMON_STRUCT;
    uint32_t chan_active;
    uint32_t chan_busy;
    uint32_t chan_busy_ext;
    uint32_t chan_self;
    uint32_t chan_rx;
    uint32_t chan_tx;
    uint32_t chan_noise;
    uint32_t duration_ms;
} target_survey_record_t;

static inline void target_client_record_free(target_client_record_t *record)
{
    if (NULL != record)
        free(record);
}

static inline void target_survey_record_free(target_survey_record_t *record)
{
    if (NULL != record)
        free(record);
}

#endif /* STATS_NETLINK_H_INCLUDED */
