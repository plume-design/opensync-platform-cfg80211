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

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>

#include "log.h"
#include "memutil.h"
#include "os_time.h"
#include "target.h"

#include "hw_acc.h"

#define sizeof_array(a) ((sizeof(a)) / (sizeof(a[0])))
#define btoerr(b) (b == true) ? 0 : -1;

typedef struct
{
    int (*cmd)(int argc, char *argv[]);
    char *name;
    char *use;
} cfgcli_cmd_t;

static int cfgcli_ae(int argc, char *argv[])
{
    if (argc < 3) return -1;

    if (strcmp(argv[2], "flush") == 0)
    {
        if (argc == 3)
        {
            printf("Flush ALL\n");
            return btoerr(hw_acc_flush_all_flows());
        }
        else if ((argc == 5) && strcmp(argv[3], "mac") == 0)
        {
            printf("Flush mac: %s\n", argv[4]);
            return btoerr(hw_acc_flush_flow_per_mac(argv[4]));
        }
    }
    else if ((argc == 4) && strcmp(argv[2], "enable") == 0)
    {
        if (strcmp(argv[3], "1") == 0)
            hw_acc_enable();
        else
            hw_acc_disable();
        return 0;
    }

    return -1;
}

static int cfgcli_help(int argc, char *argv[]);
static cfgcli_cmd_t const cfgcli_cmds[] = {
    {cfgcli_help, "help", "displays this help"},
    {cfgcli_ae, "ae", "<enable><0/1>|<flush>|<flush><mac>[mac]"},
};

static int cfgcli_help(int argc, char *argv[])
{
    uint i;

    printf("cfgcli [ARGs]\n");
    for (i = 0; i < sizeof_array(cfgcli_cmds); i++)
        printf("cmd: %s, use: %s\n", cfgcli_cmds[i].name, cfgcli_cmds[i].use);

    printf("\n");
    return 0;
}

int main(int argc, char *argv[])
{
    uint i;

    target_log_open("cfgcli", LOG_OPEN_DEFAULT | LOG_OPEN_STDOUT);
    log_severity_set(LOG_SEVERITY_TRACE);

    if (argc == 1) return cfgcli_help(argc, argv);

    for (i = 0; i < sizeof_array(cfgcli_cmds); i++)
    {
        if (strcmp(cfgcli_cmds[i].name, (char *)argv[1]) == 0) return cfgcli_cmds[i].cmd(argc, argv);
    }

    printf("unknown cmd\n");
    return -1;
}