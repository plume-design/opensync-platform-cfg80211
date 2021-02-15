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

#include "log.h"

int32_t hextonum(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int hextobin(const char *hex, size_t h_len, uint8_t *binbuf, size_t *b_len)
{
    size_t i;
    int a;
    int b1;
    int b2;
    const char *h_pos = hex;
    uint8_t *b_pos = binbuf;
    *b_len = 0;

    for (i = 0; i < h_len; i++) {
        b1 = hextonum(*h_pos++);
        if (b1 < 0)
            return -1;
        b2 = hextonum(*h_pos++);
        if (b2 < 0)
            return -1;
        a = (b1 << 4) | b2;
        if (a < 0)
            return -1;
        *b_pos++ = a;
        (*b_len)++;
    }

    return 0;
}

int bintohex(const uint8_t *binbuf, size_t isize, char *hexbuf, size_t osize)
{
    char *p;
    int i;

    if (osize < (isize * 2 + 1))
        return -1;

    memset(hexbuf, 0, osize);
    p = &hexbuf[0];

    for (i = 0; i < isize; i++)
        p += sprintf(p, "%02hhx", binbuf[i]);

    return 0;
}

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
