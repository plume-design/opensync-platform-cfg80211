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

void mac_dump(char *mac_addr, const unsigned char *arg)
{
        sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
                arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
}

int util_get_temp_info(const char *phyname)
{
    char path_temp[120] = { 0 };
    const char *buf_temp;

    if (strcmp(phyname, "phy0") == 0)
        snprintf(path_temp, sizeof(path_temp), CONFIG_MAC80211_WIPHY_PATH"/%s/device/hwmon/hwmon0/temp1_input", phyname);
    else if (strcmp(phyname, "phy1") == 0)
        snprintf(path_temp, sizeof(path_temp), CONFIG_MAC80211_WIPHY_PATH"/%s/device/hwmon/hwmon1/temp1_input", phyname);
    else if (strcmp(phyname, "phy2") == 0)
        snprintf(path_temp, sizeof(path_temp), CONFIG_MAC80211_WIPHY_PATH"/%s/device/hwmon/hwmon2/temp1_input", phyname);
    else
        return -EINVAL;

    buf_temp = strexa("cat", path_temp);
    if (!buf_temp)
        return -EINVAL;

    return strtol(buf_temp, 0, 10);
}

int util_sys_ifname_to_idx(const char *ifname)
{
    char path_ifidx[120] = { 0 };
    const char *buf_ifidx;

    snprintf(path_ifidx, sizeof(path_ifidx), "/sys/class/net/%s/ifindex", ifname);
    buf_ifidx = strexa("cat", path_ifidx);
    if (!buf_ifidx)
        return -EINVAL;

    return strtol(buf_ifidx, 0, 10);
}

int util_sys_phyname_to_idx(const char *phyname)
{
    char path_ifidx[120] = { 0 };
    const char *buf_ifidx;

    snprintf(path_ifidx, sizeof(path_ifidx), "/sys/class/ieee80211/%s/index", phyname);
    buf_ifidx = strexa("cat", path_ifidx);
    if (!buf_ifidx)
        return -EINVAL;
    return strtol(buf_ifidx, 0, 10);
}

int util_freq_to_chan(int freq)
{
    if (freq < 2412)
        return 0;

    if (freq < 5000)
        return (1 + ((freq - 2412) / 5));
    else if (freq < 6000)
        return ((freq - 5000) / 5);

    return 0;
}

int util_chan_to_freq(int chan)
{
    if (chan == 14)
        return 2484;
    else if (chan < 14)
        return 2407 + chan * 5;
    else if (chan >= 182 && chan <= 196)
        return 4000 + chan * 5;
    else
        return 5000 + chan * 5;
    return 0;
}

int mode_to_nl80211_attr_iftype(const char *mode, enum nl80211_iftype *type)
{
    if (strcmp(mode, "ap") == 0)
        *type = NL80211_IFTYPE_AP;
    else if (strcmp(mode, "sta") == 0)
        *type = NL80211_IFTYPE_STATION;
    else
        return -EINVAL;

    return 0;
}

int util_ht_mode(enum nl80211_chan_width chanwidth, char *ht_mode, int len)
{
    switch (chanwidth) {
        case NL80211_CHAN_WIDTH_20_NOHT:
            return false;
        case NL80211_CHAN_WIDTH_20:
            strscpy(ht_mode, "HT20", len);
            break;
        case NL80211_CHAN_WIDTH_40:
            strscpy(ht_mode, "HT40", len);
            break;
        case NL80211_CHAN_WIDTH_80:
            strscpy(ht_mode, "HT80", len);
            break;
        case NL80211_CHAN_WIDTH_80P80:
            strscpy(ht_mode, "HT80P80", len);
            break;
        case NL80211_CHAN_WIDTH_160:
            strscpy(ht_mode, "HT160", len);
            break;
        default:
            return false;
    }
    return true;
}

bool util_mode(enum nl80211_iftype type, char *mode, int len)
{
    switch (type) {
        case NL80211_IFTYPE_UNSPECIFIED:
            return false;
        case NL80211_IFTYPE_ADHOC:
            strscpy(mode, "adhoc", len);
            break;
        case NL80211_IFTYPE_STATION:
            strscpy(mode, "sta", len);
            break;
        case NL80211_IFTYPE_AP:
            strscpy(mode, "ap", len);
            break;
        case NL80211_IFTYPE_AP_VLAN:
            strscpy(mode, "ap_vlan", len);
            break;
        case NL80211_IFTYPE_WDS:
            strscpy(mode, "wds", len);
            break;
        case NL80211_IFTYPE_MONITOR:
            strscpy(mode, "moni", len);
            break;
        case NL80211_IFTYPE_MESH_POINT:
            strscpy(mode, "mesh", len);
            break;
        case NL80211_IFTYPE_P2P_CLIENT:
            strscpy(mode, "p2p_cli", len);
            break;
        case NL80211_IFTYPE_P2P_GO:
            strscpy(mode, "p2p_go", len);
            break;
        case NL80211_IFTYPE_P2P_DEVICE:
            strscpy(mode, "p2p_device", len);
            break;
        case NL80211_IFTYPE_OCB:
            strscpy(mode, "ocb", len);
            break;
        case NL80211_IFTYPE_NAN:
            strscpy(mode, "nan", len);
            break;
        default:
            return false;
    }
    return true;
}
