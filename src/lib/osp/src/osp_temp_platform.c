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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <util.h>

#include "log.h"
#include "const.h"
#include "ovsdb.h"
#include "osp_tm.h"
#include "memutil.h"
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include "osp_temp.h"
#include "os_util.h"

/*
 * MTK target provide the different WiFi temperature implementation spreading
 * over the different driver releases. Furthermore the embedded WiFi thermal
 * sensor actually not precise enough to use as reference temperature source.
 * So, in MTK targets, assume it always includes external thermal sensors.
 */

#define I2C_SLAVE_ADDR           (202)
#define I2C_ZONE_TEMP_FILE       "/sys/class/hwmon/hwmon%d/%s_input"

#define MWCTL_TEMP_LINE_SUBSTR   "CurrentTemperature"

/* Mapping from 'temperature source' to 'sensor location' */
static const char *sensor_location[] =
{
    "external",    /* phy0-5G:EXT-PCIE    */
    "bottom",      /* phy1-2G:MAIN-BOTTOM */
    "top",         /* phy2-6G:MAIN-TOP    */
};

int osp_temp_get_temperature_i2c(const char *if_name, int *temp)
{
    int rv = -1;
    int fd = -1;
    int idx;
    char buf[128] = {0};
    int t;

    idx = osp_temp_get_idx_from_name(if_name);
    snprintf(buf, sizeof(buf), I2C_ZONE_TEMP_FILE,
                                         I2C_SLAVE_ADDR, sensor_location[idx]);

    fd = open(buf, O_RDONLY);
    if (fd < 0) {
        LOGE("Could not open zone temperature file: %s", buf);
        goto err;
    }

    rv = read(fd, buf, sizeof(buf));
    if (rv < 0) {
        LOGE("Could not read zone temperature: %s", buf);
        goto err;
    }

    rv = sscanf(buf, "%d\n", &t);
    if (rv != 1) {
        LOGE("Could not parse zone temperature: %s", buf);
        goto err;
    }

    *temp = t/1000 + ((t % 1000) >= 500 ? 1 : 0);

    rv = 0;

err:
    if (fd >= 0) {
        close(fd);
    }

    return rv;
}

static int parse_mwctl_temp_line(char* line)
{
    long parsed_val;
    char *token = strtok(line, " ");
    int token_count = 0;

    /* The third token separated by whitespace is the temperature value */
    while (token != NULL) {
        token_count++;
        if (token_count == 3) {
            if (!os_strtoul(token, &parsed_val, 0)) {
                LOGW("%s: Error converting token to integer: '%s'", __func__, token);
                return -1;
            }
            return (int)parsed_val;
        }
        token = strtok(NULL, " ");
    }

    return -1;
}

int osp_temp_get_temperature_mwctl(const char *if_name, int *temp)
{
    char *buf = strexa("mwctl", if_name, "stat");

    if (errno == ENOENT) {
        LOGI("%s: Interface %s does not exist.", __func__, if_name);
        return false;
    }

    if (WARN_ON(buf == NULL)) return -1;

    /*
     * Parse the line containing the temperature from the mwctl <if_name> stat command:
     *   root@opensync:~# mwctl ra0 stat | grep Temp
     *   CurrentTemperature			 = 46
     */
    char *line;
    while ((line = strsep(&buf, "\n")) != NULL) {
        if (strstr(line, MWCTL_TEMP_LINE_SUBSTR) != NULL) {
            *temp = parse_mwctl_temp_line(line);
            if (*temp < 0) {
                LOGW("%s: Unable to parse temperature line for %s: %s", __func__, if_name, line);
                return -1;
            }
            return 0;
        }
    }

    return -1;
}
