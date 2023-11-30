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

/* wphy_info - wireless phy info
 *
 * - provides runtime wireless phy info on the system
 * - caches info due to expensive calls
 * - uses static storage for simplicity
 */

/* external */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <glob.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* internal */
#define MODULE_ID LOG_MODULE_ID_TARGET
#include "target.h"
#include "log.h"
#include "wiphy_info.h"
#include "util.h"
#include "target_nl80211.h"

/* static data */
static const char *wiphy_prefix = CONFIG_MAC80211_WIPHY_PREFIX;
#define TARGET_WIPHY_PATH CONFIG_MAC80211_WIPHY_PATH

static const struct {
    unsigned short device;
    unsigned short vendor;
    const char *dtcompat;
    const char *chip;
    const char *codename;
} g_chips[] = {
    // QCA
    { 0, 0, "qcom,ipq4019-wifi", "qca4019", "Dakota"},
    { 0, 0, "qcom,cnss-qca6018", "qca6018", "Cypress"},
    { 0x0056, 0x168c, "qcom,ath10k", "qca9886", "Besra"},
    // MTK
    { 0, 0, "mediatek,mt7622-wmac", "mt7622", "MediaTek"},
    { 0, 0, "mediatek,wbsys", "mt7986", "Filogic830(Panther)"},
    { 0, 0, "mediatek,mt7988-wbsys", "mt7988", "Filogic880(Jaguar)"},
    { 0x7615, 0x14c3, 0, "mt7615", "MediaTek"},
    { 0x7915, 0x14c3, 0, "mt7915", "Filogic615(Harrier)"},
    { 0x7906, 0x14c3, "ecnt,pcie-ecnt", "mt7916", "Filogic630(Merlin)"},
    { 0x7990, 0x14c3, 0, "mt7996", "Filogic680(Eagle)"},
};

/* runtime data */
static struct wiphy_info g_wiphys[4];
static char g_wiphy_2ghz_ifname[64];

/* helpers */
static int
identify_chip(const char *phyname,
              const char **chip,
              const char **codename)
{
    unsigned short device;
    unsigned short vendor;
    const char *buf_device;
    const char *buf_vendor;
    const char *buf_dtcompat;
    const char *dtcompat;
    char path_base[64];
    char path_device[64];
    char path_vendor[64];
    char path_dtcompat[64];
    bool is_da_maybe;
    glob_t g;
    size_t i;

    snprintf(path_base, sizeof(path_base),
             TARGET_WIPHY_PATH"/%s/device", phyname);
    snprintf(path_device, sizeof(path_device),
             TARGET_WIPHY_PATH"/%s/device/device", phyname);
    snprintf(path_vendor, sizeof(path_vendor),
             TARGET_WIPHY_PATH"/%s/device/vendor", phyname);
    snprintf(path_dtcompat, sizeof(path_dtcompat),
             TARGET_WIPHY_PATH"/%s/device/of_node/compatible", phyname);

    /* qca_da driver doesn't register `device` node properly so it's impossible
     * to track back wifiX netdev back to the device node. The of_node is still
     * there and can be found albeit not tied directly to the netdev.
     */
    is_da_maybe = access(path_base, X_OK) != 0;
    if (is_da_maybe) {
        if (WARN_ON(glob("/sys/devices/platform/*.wifi/of_node/compatible", 0, NULL, &g)))
            return -1;

        if (g.gl_pathc > 0)
            STRSCPY(path_dtcompat, g.gl_pathv[0]);

        i = g.gl_pathc;
        globfree(&g);

        if (i != 1) {
            LOGW("%s: unable to identify, glob() returned %zu matches", phyname, i);
            return -1;
        }
    }

    buf_device = strexa("cat", path_device) ?: "0";
    buf_vendor = strexa("cat", path_vendor) ?: "0";
    buf_dtcompat = strexa("cat", path_dtcompat) ?: "";
    device = strtol(buf_device, 0, 16);
    vendor = strtol(buf_vendor, 0, 16);
    dtcompat = buf_dtcompat;

    LOGD("%s: is_da_maybe: %d", phyname, is_da_maybe ? 1 : 0);
    LOGD("%s: device: '%s' => '%s' (%hu)", phyname, path_device, buf_device, device);
    LOGD("%s: vendor: '%s' => '%s' (%hu)", phyname, path_vendor, buf_vendor, vendor);
    LOGD("%s: dtcompat: '%s' => '%s'", phyname, path_dtcompat, buf_dtcompat);

    if (strlen(dtcompat) <= 0)
        dtcompat = NULL;

    for (i = 0; i < ARRAY_SIZE(g_chips); i++) {
        if (dtcompat) {
            if (g_chips[i].dtcompat &&
                !strcmp(dtcompat, g_chips[i].dtcompat))
                break;
        } else {
            if (device == g_chips[i].device &&
                vendor == g_chips[i].vendor)
                break;
        }
    }

    if (i == ARRAY_SIZE(g_chips))
        return -1;

    *chip = g_chips[i].chip;
    *codename = g_chips[i].codename;
    LOGD("%s: identified as: chip=%s codename=%s", phyname, *chip, *codename);

    return 0;
}

void
chan_classify(int c, int *flags)
{
    if (c >= 1 && c <= 20)
        *flags |= CHAN_2GHZ;
    if (c >= 36 && c < 100)
        *flags |= CHAN_5GHZ_LOWER;
    if (c >= 100)
        *flags |= CHAN_5GHZ_UPPER;
}

static const char *
chan_get_band_str(int flags)
{
    if (flags & CHAN_2GHZ)
        return "2.4G";
    else if ((flags & CHAN_5GHZ_LOWER) && (flags & CHAN_5GHZ_UPPER))
        return "5G";
    else if (flags & CHAN_5GHZ_LOWER)
        return "5GL";
    else if (flags & CHAN_5GHZ_UPPER)
        return "5GU";
    else if (flags & CHAN_6GHZ)
        return "6G";

    WARN_ON(1);
    return NULL;
}

static int
identify_band_nl80211(struct nl_global_info *nl_global,
                          const char *phyname,
                          const char **band)
{
    int flags = 0;

    if ((flags = nl_req_get_iface_supp_band(nl_global, phyname)) > 0) {
        *band = chan_get_band_str(flags);
        LOGI("identify band: %s", *band);
    }

    return *band ? 0 : -ENOENT;
}

static int
identify_band(struct nl_global_info *nl_global,
              const char *phyname,
              const char **band)
{
    int err;

    err = identify_band_nl80211(nl_global, phyname, band);

    return err;
}

static int
wiphy_get_idx(const char *phyname)
{
    int idx;

    idx = atoi(phyname + strlen(wiphy_prefix));
    if (WARN_ON(idx >= (int)ARRAY_SIZE(g_wiphys)))
        return -1;
    if (WARN_ON(idx < 0))
        return -1;

    return idx;
}

static int
wiphy_info_init_ifname(struct nl_global_info *nl_global, const char *phyname)
{
    struct wiphy_info *info;
    int idx;

    idx = wiphy_get_idx(phyname);
    if (WARN_ON(idx < 0))
        return -1;

    info = &g_wiphys[idx];

    if (WARN_ON(identify_chip(phyname, &info->chip, &info->codename)))
        return -1;

    if (WARN_ON(identify_band(nl_global, phyname, &info->band)))
        return -1;

    if (WARN_ON(!info->band))
        return -1;

    if (!strcmp(info->chip, "mt7996")) {
        // Wifi 7
        info->mode = "11be";
    } else if (!strcmp(info->chip, "mt7915") ||
               !strcmp(info->chip, "mt7916") ||
               !strcmp(info->chip, "mt7986")) {
        // Wifi 6/6E
        info->mode = "11ax";
    } else if (!strcmp(info->chip, "qca4019") ||
               !strcmp(info->chip, "qca6018") ||
               !strcmp(info->chip, "qca9886") ||
               !strcmp(info->chip, "mt7615")) {
        // Wifi 5
        if (strstr(info->band, "5G") == info->band)
            info->mode = "11ac";  // 5G, 5GL, 5GU
        else if (!strcmp(info->band, "2.4G"))
            info->mode = "11n";
    } else if (!strcmp(info->chip, "mt7622")) {
        // Wifi 4
        info->mode = "11n";
    }

    if (!strcmp(info->band, "2.4G"))
        STRSCPY(g_wiphy_2ghz_ifname, phyname);

    return 0;
}

/* public */
const char *
wiphy_info_get_2ghz_ifname(void)
{
    return g_wiphy_2ghz_ifname;
}

const struct wiphy_info *
wiphy_info_get(const char *ifname)
{
    struct wiphy_info *info;
    int idx;

    idx = wiphy_get_idx(ifname);
    if (WARN_ON(idx < 0))
        return NULL;

    info = &g_wiphys[idx];
    if (WARN_ON(!info->chip))
        return NULL;
    if (WARN_ON(!info->codename))
        return NULL;
    if (WARN_ON(!info->band))
        return NULL;
    if (WARN_ON(!info->mode))
        return NULL;

    LOGD("%s: wiphy_info_get: chip=%s codename=%s band=%s mode=%s", ifname, info->chip, info->codename, info->band, info->mode);

    return info;
}

int
wiphy_info_init(struct nl_global_info *nl_global)
{
    struct dirent *i;
    DIR *d;

    if (WARN_ON(!(d = opendir(TARGET_WIPHY_PATH))))
        return -1;

    while ((i = readdir(d)))
        if (strstr(i->d_name, wiphy_prefix) == i->d_name)
            if (WARN_ON(wiphy_info_init_ifname(nl_global, i->d_name)))
                break;

    closedir(d);
    return i == NULL ? 0 : -1;
}
