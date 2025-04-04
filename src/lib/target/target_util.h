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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef TARGET_UTIL_H_INCLUDED
#define TARGET_UTIL_H_INCLUDED
#include <stdbool.h>

#define D(name, fallback) ((name##_exists) ? (name) : (fallback))
#define A(size) alloca(size), size
#define E(prog, ...) forkexec(prog, (const char *[]){prog, __VA_ARGS__, NULL}, NULL, NULL, 0)
#define F(fmt, ...) \
    ({ \
        char *__p = alloca(4096); \
        memset(__p, 0, 4096); \
        snprintf(__p, 4095, fmt, ##__VA_ARGS__); \
        __p; \
    })
#define R(...) file_geta(__VA_ARGS__)
#define timeout_arg "timeout", "-s", "KILL", "-t", "3"
#define runcmd(...) readcmd(__VA_ARGS__)
#define WARN(cond, ...) (cond && (LOGW(__VA_ARGS__), 1))
#define util_exec_read(xfrm, buf, len, prog, ...) \
    forkexec(prog, (const char *[]){prog, __VA_ARGS__, NULL}, xfrm, buf, len)
#define util_exec_simple(prog, ...) forkexec(prog, (const char *[]){prog, __VA_ARGS__, NULL}, NULL, NULL, 0)
#define util_exec_expect(str, ...) \
    ({ \
        char buf[32]; \
        int err = util_exec_read(rtrimnl, buf, sizeof(buf), __VA_ARGS__); \
        err || strcmp(str, buf); \
    })

int util_wifi_get_parent(const char *vif, char *buf, int len);
bool util_wifi_is_phy_vif_match(const char *phy, const char *vif);
int util_get_vif_radio(const char *in_vif, char *phy_buf, int len);
int util_wifi_get_phy_all_vifs(const char *phy, char *buf, int len);
int util_file_read(const char *path, char *buf, int len);
int util_file_write(const char *path, const char *buf, int len);
int util_file_read_str(const char *path, char *buf, int len);

#endif /* TARGET_UTIL_H_INCLUDED */
