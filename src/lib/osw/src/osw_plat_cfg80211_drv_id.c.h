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

enum osw_plat_cfg80211_drv_id
{
    OSW_PLAT_CFG80211_DRV_ID_UNKNOWN,
    OSW_PLAT_CFG80211_DRV_ID_MT76,     /* open source */
    OSW_PLAT_CFG80211_DRV_ID_MTK_WIFI, /* closed source */
};

static const char *osw_plat_cfg80211_drv_id_to_cstr(enum osw_plat_cfg80211_drv_id driver)
{
    switch (driver)
    {
        case OSW_PLAT_CFG80211_DRV_ID_UNKNOWN:
            return "unknown";
        case OSW_PLAT_CFG80211_DRV_ID_MT76:
            return "mt76";
        case OSW_PLAT_CFG80211_DRV_ID_MTK_WIFI:
            return "mtk_wifi";
    }
    WARN_ON(1);
    return "???";
}

static enum osw_plat_cfg80211_drv_id osw_plat_cfg80211_drv_id_get(const char *phy_name)
{
    const char *path = strfmta("/sys/class/ieee80211/%s/device/driver", phy_name);
    char buf[PATH_MAX];
    const ssize_t len = os_readlink(path, buf, sizeof(buf));
    if (len < 0) return OSW_PLAT_CFG80211_DRV_ID_UNKNOWN;
    char *name = basename(buf);
    if (name == NULL) return OSW_PLAT_CFG80211_DRV_ID_UNKNOWN;
    if (strcmp(name, "mt7915e") == 0) return OSW_PLAT_CFG80211_DRV_ID_MT76;
    if (strcmp(name, "mt7990") == 0) return OSW_PLAT_CFG80211_DRV_ID_MTK_WIFI;
    return OSW_PLAT_CFG80211_DRV_ID_UNKNOWN;
}

static bool osw_plat_cfg80211_drv_id_is_unknown(const char *phy_name)
{
    return osw_plat_cfg80211_drv_id_get(phy_name) == OSW_PLAT_CFG80211_DRV_ID_UNKNOWN;
}

static bool osw_plat_cfg80211_has_mwctl(const char *phy_name)
{
    return (osw_plat_cfg80211_drv_id_get(phy_name) == OSW_PLAT_CFG80211_DRV_ID_MTK_WIFI);
}
