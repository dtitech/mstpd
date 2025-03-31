/*****************************************************************************
  Copyright (c) 2011 Factor-SPE

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the Free
  Software Foundation; either version 2 of the License, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc., 59
  Temple Place - Suite 330, Boston, MA  02111-1307, USA.

  The full GNU General Public License is included in this distribution in the
  file called LICENSE.

  Authors: Vitalii Demianets <dvitasgs@gmail.com>

******************************************************************************/

#include <config.h>

#include <string.h>
#include <getopt.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#include "ctl_socket_client.h"
#include "log.h"

int main(int argc, char *const *argv)
{
    const struct command *cmd;
    int f, rc;
    static const struct option options[] =
    {
        {.name = "help",    .val = 'h'},
        {.name = "version", .val = 'V'},
        {.name = "batch",   .val = 'b', .has_arg = 1},
        {.name = "stdin",   .val = 's'},
        {.name = "ignore",  .val = 'i'},
        {.name = "format",  .val = 'f', .has_arg = 1},
        {0}
    };
    FILE *batch_file = NULL;
    bool is_stdin = false;
    bool ignore = false;

    while(EOF != (f = getopt_long(argc, argv, "Vhf:b:is", options, NULL)))
        switch(f)
        {
            case 'h':
                help();
                return 0;
            case 'V':
                printf(PACKAGE_VERSION "\n");
                return 0;
            case 'b':
                if (is_stdin) {
                    fprintf(stderr, "Cannot mix stdin & batch file\n");
                    goto help;
                }
                if (!optarg || !strlen(optarg)) {
                    fprintf(stderr, "No batch file provided\n");
                    goto help;
                }
                batch_file = fopen(optarg, "rb");
                if (!batch_file) {
                    fprintf(stderr, "Could not open file '%s'\n", optarg);
                    goto help;
                }
                break;
            case 's':
                if (batch_file) {
                    fprintf(stderr, "Cannot mix stdin & batch file\n");
                    goto help;
                }
                batch_file = stdin;
                is_stdin = true;
                break;
            case 'i':
                ignore = true;
                break;
            case 'f':
                if (!strcmp(optarg, "json"))
                    format = FORMAT_JSON;
                else if (!strcmp(optarg, "plain"))
                    format = FORMAT_PLAIN;
                else
                {
                    fprintf(stderr, "Invalid format '%s'\n", optarg);
                    goto help;
                }
                break;
            default:
                fprintf(stderr, "Unknown option '%c'\n", f);
                goto help;
        }

    if((argc == optind) && !batch_file)
        goto help;

    if(ctl_client_init())
    {
        fprintf(stderr, "can't setup control connection\n");
        return 1;
    }

    if (batch_file) {
        rc = process_batch_cmds(batch_file, ignore, is_stdin);
        if (!is_stdin)
            fclose(batch_file);
        return rc;
    }

    argc -= optind;
    argv += optind;

    cmd = command_lookup_and_validate(argc, argv, 0);
    if(!cmd)
        return 1;

    return cmd->func(argc, argv);

help:
    help();
    return 1;
}

/* Implementation of client-side functions */
CLIENT_SIDE_FUNCTION(get_cist_bridge_status)
CLIENT_SIDE_FUNCTION(get_msti_bridge_status)
CLIENT_SIDE_FUNCTION(set_cist_bridge_config)
CLIENT_SIDE_FUNCTION(set_msti_bridge_config)
CLIENT_SIDE_FUNCTION(get_cist_port_status)
CLIENT_SIDE_FUNCTION(get_msti_port_status)
CLIENT_SIDE_FUNCTION(set_cist_port_config)
CLIENT_SIDE_FUNCTION(set_msti_port_config)
CLIENT_SIDE_FUNCTION(port_mcheck)
CLIENT_SIDE_FUNCTION(set_debug_level)
CLIENT_SIDE_FUNCTION(get_mstilist)
CLIENT_SIDE_FUNCTION(create_msti)
CLIENT_SIDE_FUNCTION(delete_msti)
CLIENT_SIDE_FUNCTION(get_mstconfid)
CLIENT_SIDE_FUNCTION(set_mstconfid)
CLIENT_SIDE_FUNCTION(get_vids2mstids)
CLIENT_SIDE_FUNCTION(set_vid2mstid)
CLIENT_SIDE_FUNCTION(set_vids2mstids)

CTL_DECLARE(add_bridges)
{
    int res = 0;
    LogString log = { .buf = "" };
    int i, chunk_count, brcount, serialized_data_count;
    int *serialized_data, *ptr;

    chunk_count = serialized_data_count = (brcount = br_array[0]) + 1;
    for(i = 0; i < brcount; ++i)
        serialized_data_count += ifaces_lists[i][0] + 1;
    if(NULL == (serialized_data = malloc(serialized_data_count * sizeof(int))))
    {
        LOG("out of memory, serialized_data_count = %d",
            serialized_data_count);
        return -1;
    }
    memcpy(serialized_data, br_array, chunk_count * sizeof(int));
    ptr = serialized_data + chunk_count;
    for(i = 0; i < brcount; ++i)
    {
        chunk_count = ifaces_lists[i][0] + 1;
        memcpy(ptr, ifaces_lists[i], chunk_count * sizeof(int));
        ptr += chunk_count;
    }

    int r = send_ctl_message(CMD_CODE_add_bridges, serialized_data,
                             serialized_data_count * sizeof(int),
                             NULL, 0, &log, &res);
    free(serialized_data);
    if(r || res)
        LOG("Got return code %d, %d\n%s", r, res, log.buf);
    if(r)
        return r;
    if(res)
        return res;
    return 0;
}

CTL_DECLARE(del_bridges)
{
    int res = 0;
    LogString log = { .buf = "" };
    int r = send_ctl_message(CMD_CODE_del_bridges,
                             br_array, (br_array[0] + 1) * sizeof(int),
                             NULL, 0, &log, &res);
    if(r || res)
        LOG("Got return code %d, %d\n%s", r, res, log.buf);
    if(r)
        return r;
    if(res)
        return res;
    return 0;
}

/*********************** Logging *********************/

void Dprintf(int level, const char *fmt, ...)
{
    char logbuf[LOG_STRING_LEN];
    logbuf[sizeof(logbuf) - 1] = 0;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(logbuf, sizeof(logbuf) - 1, fmt, ap);
    va_end(ap);
    printf("%s\n", logbuf);
}
