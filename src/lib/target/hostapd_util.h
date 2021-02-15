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
#ifndef HOSTAPD_UTIL_H_INCLUDED
#define HOSTAPD_UTIL_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define HOSTAPD_CONTROL_PATH_DEFAULT "/var/run"
#define EXEC(...) strexa(__VA_ARGS__)
#define CMD_TIMEOUT(...) "timeout", "-s", "KILL", "3", ## __VA_ARGS__
#define HOSTAPD_CLI(sockdir, vif, ...) EXEC(CMD_TIMEOUT("hostapd_cli", "-p", sockdir, "-i", vif, ## __VA_ARGS__))

#define SSID_MAX_LEN 32

bool hostapd_client_disconnect(const char *interface, const char *disc_type,
                               const char *mac_str, uint8_t reason);
bool hostapd_btm_request(const char *interface, const char *btm_req_cmd);
bool hostapd_rrm_set_neighbor(const char *interface, const char *bssid, const char *hex_ssid, const char *nr);
bool hostapd_rrm_remove_neighbor(const char *interface, const char *bssid);

#endif /* HOSTAPD_UTIL_H_INCLUDED */
