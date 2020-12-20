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

#include "target_ioctl.h"

#define for_each_iwpriv_mac(mac, list) \
    for (mac = strtok(list, " \t\n"); mac; mac = strtok(NULL, " \t\n")) \

static char *util_qca_getmac(const char *dvif, char *buf, int len);
int forkexec(const char *file, const char **argv, void (*xfrm)(char *), char *buf, int len);
static void argv2str(const char **argv, char *buf, int len);
void rtrimws(char *str);
void rtrimnl(char *str);
int readcmd(char *buf, size_t buflen, void (*xfrm)(char *), const char *fmt, ...);

static inline bool qca_get_int(const char *ifname, const char *iwprivname, int *v)
{
    char *p;

    char command[32] = "--";
    strcat(command,iwprivname);
    const char *argv[] = { "cfg80211tool.1", "-i", ifname, "-h", "none", "--START_CMD",
                            command, "--RESPONSE", command, "--END_CMD", NULL };

    char buf[128];
    int err;

    err = forkexec(argv[0], argv, rtrimws, buf, sizeof(buf));
    if (err < 0)
        return false;

    p = strchr(buf, ':');
    if (!p)
            return false;

    p++;
    if (strlen(p) == 0)
            return false;

    *v = atoi(p);
    LOGD("get value:%d\n",*v);
    return true;
}

static inline int qca_set_int(const char *ifname, const char *iwprivname, int v)
{
    char arg[16];
    char command[32] = "--";
    strcat(command,iwprivname);

    const char *argv[] = { "cfg80211tool.1", "-i", ifname, "-h", "none", "--START_CMD",
                            command, "--value0", arg, "--RESPONSE", command, "--END_CMD", NULL };
    char c;

    snprintf(arg, sizeof(arg), "%d", v);
    return forkexec(argv[0], argv, NULL, &c, sizeof(c));
}

static inline bool qca_get_ht_mode(const char *vif, char *htmode, int htmode_len)
{
    char buf[120];
    char *p;

    if (WARN(-1 == util_exec_read(rtrimnl, buf, sizeof(buf),
                "cfg80211tool.1", "-i", vif, "-h", "none", "--START_CMD", "--get_mode",
                "--RESPONSE", "--get_mode", "--END_CMD"),
                "%s: failed to get iwpriv :%d (%s)",
                vif, errno, strerror(errno)))
        return false;

    if (!(p = strstr(buf, ":")))
        return false;
    p++;

    strscpy(htmode, p, htmode_len);
    return true;
}

static inline int qca_set_str_lazy(const char *device_ifname,
                                    const char *iwpriv_get,
                                    const char *iwpriv_set,
                                    const char *v)
{
    char buf[64];
    char *p;
    char command_get[32] = "--";
    strcat(command_get,iwpriv_get);
    char command_set[32] = "--";
    strcat(command_set,iwpriv_set);

    if (WARN(-1 == util_exec_read(rtrimnl, buf, sizeof(buf),
            "cfg80211tool.1", "-i", device_ifname, "-h", "none", "--START_CMD", command_get,
            "--RESPONSE", command_get, "--END_CMD"),
            "%s: failed to get iwpriv '%s': %d (%s)",
            device_ifname, iwpriv_get, errno, strerror(errno)))
        return -1;

    if (!(p = strstr(buf, ":")))
        return 0;

    p++;

    if (!strcmp(p, v))
        return 0;

    LOGI("%s: setting '%s' = '%s'", device_ifname, iwpriv_set, v);
    if (WARN(-1 == util_exec_simple("cfg80211tool.1", "-i", device_ifname, "-h", "none", "--START_CMD", command_set,
                                        "--value0", v,"--RESPONSE", command_set, "--END_CMD"),
        "%s: failed to set iwpriv '%s': %d (%s)",
        device_ifname, iwpriv_get, errno, strerror(errno))) {
            LOGI("---------failed to set value:%s-----------\n",iwpriv_set);
            return -1;
    }
    return 1;
}

static inline int wlanconfig_nl80211_is_supported(const char *vif, int chan)
{
    return 0 == runcmd("wlanconfig %s list freq -cfg80211"
                        "| grep -o 'Channel[ ]*[0-9]* ' "
                        "| awk '$2 == %d' "
                        "| grep -q .",
                        vif,
                        chan);
}

static inline void wlanconfig_nl80211_list_sta(char *buf, const char* dvif)
{
    if (WARN_ON(!(buf = strexa("wlanconfig", dvif, "list", "sta", "-cfg80211"))))
        return;
}
