
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

# This depends on 51_owm.sh possibly as it can
# override OWM Node_Services configuration.

ovsh=${INSTALL_PREFIX}/tools/ovsh

owm_wanted() {
    $ovsh s Node_Services \
        -w service==owm \
        -w enable==true \
        -w status==enabled >/dev/null
}

# Legacy driver is only intended for testing, not
# actual use. But since it was designed around
# being able to create interfaces from scratch,
# let it do it. Interface creation is currently
# tied to osw_drv_nl80211 anyway.
is_legacy() {
    test -z "$OSW_DRV_TARGET_DISABLED"
}

is_not_legacy() {
    ! is_legacy
}

radio_suffix() {
    phy_name=$1
    band=$(iw phy $phy_name info | grep "Band " | cut -d ':' -f1 | cut -d ' ' -f2)
    if [ $band == "1" ]; then
        suffix="24"
    elif [ $band == "2" ]; then
        suffix="50"
    elif [ $band == "4" ]; then
        suffix="60"
    else
        exit 1
    fi
    echo $suffix
}

vap_transform_macaddr() {
    mac=$1
    idx=$2

    [ $idx -eq 0 ] && {
        echo $mac
        return
    }

    mac0=0x"$(echo "$mac" | cut -d':' -f1)"
    nmac0=$(printf "%02x" $(((((((mac0 >> 4) + 8 + idx - 2) & 0xf) << 4) | (mac0 & 0xf)) | 0x2)))
    echo "${nmac0}${mac:2}"
}

create_vap() {
    phy_name=$1
    vif_idx=$2
    vif_name=$3
    vif_type=$4

    phy_mac=$(cat /sys/class/ieee80211/$phy_name/macaddress)
    vif_mac=$(vap_transform_macaddr $phy_mac $vif_idx)
    iw dev $vif_name del
    iw phy $phy_name interface add $vif_name type $vif_type addr $vif_mac
}

create_vaps() {
    for dir in /sys/class/ieee80211/*
    do
        phy=$(basename $dir)
        suffix=$(radio_suffix $phy)
        create_vap $phy 0 bhaul-sta-$suffix station
        create_vap $phy 1 b-ap-$suffix __ap
        create_vap $phy 2 home-ap-$suffix __ap
        create_vap $phy 3 onboard-ap-$suffix __ap
        create_vap $phy 4 svc-d-ap-$suffix __ap
        create_vap $phy 5 svc-e-ap-$suffix __ap
        create_vap $phy 6 fh-$suffix __ap
        create_vap $phy 7 cp-$suffix __ap
    done
}

if owm_wanted && is_not_legacy
then
    create_vaps
fi
