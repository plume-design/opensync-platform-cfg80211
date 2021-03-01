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

#ifndef BSAL_H_INCLUDED
#define BSAL_H_INCLUDED
#include "target_bsal.h"

enum xing_level {
    SNR_NONE,
    SNR_ABOVE_HWM,
    SNR_BETWEEN_HWM_LWM,
    SNR_BELOW_LWM
};

typedef struct {
    os_macaddr_t            mac_addr;
    char                    ifname[IFNAMSIZ];
    bool                    connected;
    uint8_t                 is_BTM_supported;
    uint8_t                 is_RRM_supported;
    bool                    band_cap_2G;
    bool                    band_cap_5G;
    bsal_datarate_info_t    datarate_info;
    bsal_rrm_caps_t         rrm_caps;
    uint8_t                 assoc_ies[BSAL_MAX_ASSOC_IES_LEN];
    uint16_t                assoc_ies_len;
    uint8_t                 rssi;
    uint8_t                 snr;
    uint64_t                tx_bytes;
    uint64_t                rx_bytes;
    uint8_t                 snr_lwm_xing;
    uint8_t                 snr_hwm_xing;
    enum xing_level         xing_level;
    ds_dlist_node_t         node;
} bsal_cli_info;

int     nl_bsal_init(bsal_event_cb_t event_cb, struct ev_loop *loop);
int     nl_bsal_cleanup(void);

int     nl_bsal_iface_add(const bsal_ifconfig_t *ifcfg);
int     nl_bsal_iface_update(const bsal_ifconfig_t *ifcfg);
int     nl_bsal_iface_remove(const bsal_ifconfig_t *ifcfg);

int     nl_bsal_client_add(const char *ifname, const uint8_t *mac_addr, const bsal_client_config_t *conf);
int     nl_bsal_client_update(const char *ifname, const uint8_t *mac_addr, const bsal_client_config_t *conf);
int     nl_bsal_client_remove(const char *ifname, const uint8_t *mac_addr);

int     nl_bsal_client_measure(const char *ifname, const uint8_t *mac_addr, int num_samples);
int     nl_bsal_client_disconnect(const char *ifname, const uint8_t *mac_addr, bsal_disc_type_t type, uint8_t reason);
int     nl_bsal_client_info(const char *ifname, const uint8_t *mac_addr, bsal_client_info_t *info);

int     nl_bsal_bss_tm_request(const char *ifname, const uint8_t *mac_addr, const bsal_btm_params_t *btm_params);
int     nl_bsal_rrm_beacon_report_request(const char *ifname, const uint8_t *mac_addr, const bsal_rrm_params_t *rrm_params);

int     nl_bsal_rrm_set_neighbor(const char *ifname, const bsal_neigh_info_t *nr);
int     nl_bsal_rrm_remove_neighbor(const char *ifname, const bsal_neigh_info_t *nr);
int     nl_bsal_send_action(const char *ifname, const uint8_t *mac_addr, const uint8_t *data, unsigned int data_len);

void    bsal_nl_evt_parse_conn_failed(struct nlattr **tb);
#endif /* BSAL_H_INCLUDED */
