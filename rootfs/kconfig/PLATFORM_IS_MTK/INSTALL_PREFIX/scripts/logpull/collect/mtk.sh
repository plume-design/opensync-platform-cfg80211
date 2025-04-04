#!/bin/sh

# Copyright (c) 2020, Plume Design Inc. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#    3. Neither the name of the Plume Design Inc. nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# {# jinja-parse #}

#
# Collect MTK info
#
. "$LOGPULL_LIB"

collect_mtkwl()
{
    for phy in /sys/kernel/debug/ieee80211/*
    do
        # TX queue
        collect_file $phy/mt76/token
    done
}

collect_mtkaccel()
{
    collect_file /sys/kernel/debug/xt_flowoffload/enable
    collect_file /sys/kernel/debug/xt_flowoffload/hooks
}

collect_mtkmcast()
{
    collect_file /sys/devices/virtual/net/{{CONFIG_TARGET_LAN_BRIDGE_NAME}}/bridge/multicast_snooping
    collect_file /sys/kernel/debug/xt_flowoffload/hooks

    for if in /sys/devices/virtual/net/{{CONFIG_TARGET_LAN_BRIDGE_NAME}}/brif/*
    do
        # MU2
        collect_file "$if"/multicast_to_unicast
    done
}

collect_platform_mtk()
{
    collect_mtkwl
    collect_mtkaccel
    collect_mtkmcast
}

collect_platform_mtk
