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


HNAT_DIR=/sys/kernel/debug/hnat
HNAT_CONFIG=hnat_setting

# ====================Advanced Settings====================
# Usage: echo [type] [option] > /sys/kernel/debug/hnat/hnat_setting
#
# Commands:   [type] [option]
#               0     0~7        Set debug_level(0~7), current debug_level=0
#               1     0~65535    Set binding threshold
#               2     0~65535    Set TCP bind lifetime
#               3     0~65535    Set FIN bind lifetime
#               4     0~65535    Set UDP bind lifetime
#               5     0~255      Set TCP keep alive interval
#               6     0~255      Set UDP keep alive interval
#               7     0~1        Set hnat counter update to nf_conntrack
#               8     0~6        Set PPE hash debug mode
#               9     0~4G       Set hnat counter update interval in ms (0 disabled)

if [ -e  $HNAT_DIR/$HNAT_CONFIG ]; then
	echo 7 0 > $HNAT_DIR/$HNAT_CONFIG

	echo 2 2 > $HNAT_DIR/$HNAT_CONFIG
	echo 3 2 > $HNAT_DIR/$HNAT_CONFIG
	echo 4 2 > $HNAT_DIR/$HNAT_CONFIG

	echo 9 1000 > $HNAT_DIR/$HNAT_CONFIG
fi
