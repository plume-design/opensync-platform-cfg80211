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
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#include "log.h"
#include "target_util.h"
#include "util.h"
#include "os_common.h"


int util_wifi_get_parent(const char *vif, char *buf, int len)
{
    char p_buf[32] = {0};

    if (util_get_vif_radio(vif, p_buf, sizeof(p_buf))) {
        LOGW("%s: failed to get vif radio", vif);
        return -EINVAL;
    }
    strscpy(buf, p_buf, len);

    return 0;
}

bool util_wifi_is_phy_vif_match(const char *phy, const char *vif)
{
    char buf[32];
    util_wifi_get_parent(vif, buf, sizeof(buf));
    return !strcmp(phy, buf);
}


int
util_wifi_get_phy_all_vifs(const char *phy,
                       char *buf,
                       int len)
{
    struct dirent *p;
    char phy_path[BFR_SIZE_256];
    DIR *d;
    char *phy_name;

    memset(buf, 0, len);

    snprintf(phy_path, sizeof(phy_path), CONFIG_MAC80211_WIPHY_PATH"/%s/device/net", phy);
    if (!(d = opendir(phy_path)))
        return -1;

    for (p = readdir(d); p ; p = readdir(d)) {
        if (p->d_name && strncmp(p->d_name, ".", 1)) {
            phy_name = strchomp(R(F(CONFIG_MAC80211_WIPHY_PATH"/%s/device/net/%s/phy80211/name",
                            phy, p->d_name)), "\r\n ");

            if (!strcmp(phy_name, phy)) {
                snprintf(buf + strlen(buf), len - strlen(buf), "%s ", p->d_name);
            }
        }
    }

    closedir(d);
    return 0;
}

int
util_file_read(const char *path, char *buf, int len)
{
    int fd;
    int err;
    int errno2;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    err = read(fd, buf, len);
    errno2 = errno;
    close(fd);
    errno = errno2;
    return err;
}

int
util_file_write(const char *path, const char *buf, int len)
{
    int fd;
    int err;
    int errno2;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    err = write(fd, buf, len);
    errno2 = errno;
    close(fd);
    errno = errno2;
    return err;
}

int
util_file_read_str(const char *path, char *buf, int len)
{
    int rlen;
    buf[0] = 0;
    rlen = util_file_read(path, buf, len);
    if (rlen < 0)
        return rlen;
    buf[rlen] = 0;
    LOGT("%s: '%s' (%d)", path, buf, rlen);
    return rlen;
}
