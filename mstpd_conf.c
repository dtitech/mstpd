/*****************************************************************************
  Copyright (c) 2025 DTI Technologies s.r.o.

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

  Authors: Tomas Kyzlink <tkyzlink@dtitech.cz>

******************************************************************************/

#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <asm/byteorder.h>

#include "io_buffer.h"
#include "log.h"

#include "mstpd_conf.h"

#define MAX_MAX_AGE 255
#define MAX_FORWARD_DELAY 255
#define MAX_HOPS 255
#define MAX_HELLO 255
#define MAX_TX_HOLD_COUNT 255
#define MAX_CONFIG_REV 0xFFFF
#define MAX_BR_PRIO 65535
#define MAX_PRT_PRIO 240
#define MAX_COST 210000000

#define MSTID_PAGE_SIZE 128
#define LINE_PAGE_SIZE 128

#define CTX_DBG(_ctx, _fmt, _args...) \
    Dprintf(LOG_LEVEL_DEBUG, "%s: [%s:%d] " _fmt, __PRETTY_FUNCTION__, \
            (_ctx)->filename, (_ctx)->line, ##_args)

#define CTX_INF(_ctx, _fmt, _args...) \
    Dprintf(LOG_LEVEL_INFO, "%s: [%s:%d] " _fmt, __PRETTY_FUNCTION__, \
            (_ctx)->filename, (_ctx)->line, ##_args)

#define CTX_ERR(_ctx, _fmt, _args...) \
    Dprintf(LOG_LEVEL_ERROR, "%s: [%s:%d] " _fmt, __PRETTY_FUNCTION__, \
            (_ctx)->filename, (_ctx)->line, ##_args)

struct conf_br_mstid
{
    __u16 id;
    bool set;
    __u16 prio;
    bool prio_set;
};

struct conf_prt_mstid
{
    __u16 id;
    bool set;
    __u16 prio;
    bool prio_set;
    __u32 int_cost;
    bool int_cost_set;
};

struct conf_br
{
    protocol_version_t mode;
    bool mode_set;
    __u8 max_age;
    bool max_age_set;
    __u8 forward_delay;
    bool forward_delay_set;
    __u8 max_hops;
    bool max_hops_set;
    __u8 hello;
    bool hello_set;
    unsigned int ageing;
    bool ageing_set;
    unsigned int tx_hold_count;
    bool tx_hold_count_set;
    __u16 confid_rev;
    bool confid_set;
    __u8 confid_name[CONFIGURATION_NAME_LEN];
    __u16 prio;
    bool prio_set;
    struct conf_br_mstid *mstids;
    size_t mstids_sz;
    size_t mstids_cnt;
    __u16 vid2mstid[MAX_VID + 2];
    bool vid2mstid_set;
};

struct conf_prt
{
    bool admin_edge;
    bool admin_edge_set;
    bool auto_edge;
    bool auto_edge_set;
    admin_p2p_t p2p;
    bool p2p_set;
    bool rest_role;
    bool rest_role_set;
    bool rest_tcn;
    bool rest_tcn_set;
    bool bpdu_guard;
    bool bpdu_guard_set;
    bool network;
    bool network_set;
    bool dont_txmt;
    bool dont_txmt_set;
    bool bpdu_filter;
    bool bpdu_filter_set;
    __u16 prio;
    bool prio_set;
    __u32 int_cost;
    bool int_cost_set;
    __u32 ext_cost;
    bool ext_cost_set;
    struct conf_prt_mstid *mstids;
    size_t mstids_sz;
    size_t mstids_cnt;
};

struct conf_if
{
    union
    {
        struct conf_br br;
        struct conf_prt prt;
    };
};

struct conf_opt;

struct conf_ctx
{
    union
    {
        struct conf_br *br;
        struct conf_prt *prt;
        struct conf_if *cif;
    };
    const char *filename;
    int line;
    const char *optname;
    int mstid;
    char **argv;
    int argc;
};

struct conf_opt
{
    const char *name;
    int argc_min;
    int argc_max;
    int (*func) (struct conf_ctx *ctx);
};

const char *conf_opt_mode[] = { "stp", "rstp", "mstp", NULL };
const char *conf_opt_yesno[] = { "no", "yes", NULL };
const char *conf_opt_yesnoauto[] = { "no", "yes", "auto", NULL };

static int conf_opt_br_mode(struct conf_ctx *ctx);
static int conf_opt_br_max_age(struct conf_ctx *ctx);
static int conf_opt_br_forward_delay(struct conf_ctx *ctx);
static int conf_opt_br_max_hops(struct conf_ctx *ctx);
static int conf_opt_br_hello(struct conf_ctx *ctx);
static int conf_opt_br_ageing(struct conf_ctx *ctx);
static int conf_opt_br_tx_hold_count(struct conf_ctx *ctx);
static int conf_opt_br_confid(struct conf_ctx *ctx);
static int conf_opt_br_mstid(struct conf_ctx *ctx);
static int conf_opt_br_prio(struct conf_ctx *ctx);
static int conf_opt_br_vids(struct conf_ctx *ctx);

const struct conf_opt conf_opts_br[] =
{
    { "mode", 1, 1, conf_opt_br_mode },
    { "max-age", 1, 1, conf_opt_br_max_age },
    { "forward-delay", 1, 1, conf_opt_br_forward_delay },
    { "max-hops", 1, 1, conf_opt_br_max_hops },
    { "hello", 1, 1, conf_opt_br_hello },
    { "ageing", 1, 1, conf_opt_br_ageing },
    { "tx-hold-count", 1, 1, conf_opt_br_tx_hold_count },
    { "confid", 2, 2, conf_opt_br_confid },
    { "mstid", 1, 1, conf_opt_br_mstid },
    { "prio", 1, 1, conf_opt_br_prio },
    { "vids", 1, 0, conf_opt_br_vids },
    { NULL, 0, 0, NULL }
};

static int conf_opt_prt_admin_edge(struct conf_ctx *ctx);
static int conf_opt_prt_auto_edge(struct conf_ctx *ctx);
static int conf_opt_prt_p2p(struct conf_ctx *ctx);
static int conf_opt_prt_rest_role(struct conf_ctx *ctx);
static int conf_opt_prt_rest_tcn(struct conf_ctx *ctx);
static int conf_opt_prt_bpdu_guard(struct conf_ctx *ctx);
static int conf_opt_prt_network(struct conf_ctx *ctx);
static int conf_opt_prt_dont_txmt(struct conf_ctx *ctx);
static int conf_opt_prt_bpdu_filter(struct conf_ctx *ctx);
static int conf_opt_prt_mstid(struct conf_ctx *ctx);
static int conf_opt_prt_prio(struct conf_ctx *ctx);
static int conf_opt_prt_int_cost(struct conf_ctx *ctx);
static int conf_opt_prt_ext_cost(struct conf_ctx *ctx);

const struct conf_opt conf_opts_prt[] =
{
    { "admin-edge", 1, 1, conf_opt_prt_admin_edge },
    { "auto-edge", 1, 1, conf_opt_prt_auto_edge },
    { "p2p", 1, 1, conf_opt_prt_p2p },
    { "rest-role", 1, 1, conf_opt_prt_rest_role },
    { "rest-tcn", 1, 1, conf_opt_prt_rest_tcn },
    { "bpdu-guard", 1, 1, conf_opt_prt_bpdu_guard },
    { "network", 1, 1, conf_opt_prt_network },
    { "dont-txmt", 1, 1, conf_opt_prt_dont_txmt },
    { "bpdu-filter", 1, 1, conf_opt_prt_bpdu_filter },
    { "mstid", 1, 1, conf_opt_prt_mstid },
    { "prio", 1, 1, conf_opt_prt_prio },
    { "int-cost", 1, 1, conf_opt_prt_int_cost },
    { "ext-cost", 1, 1, conf_opt_prt_ext_cost },
    { NULL, 0, 0, NULL }
};

/*****************************************************************************
  Helper functions
*****************************************************************************/

static int str_getuint(const char *s, unsigned int *value)
{
    char *end;
    unsigned long l;
    l = strtoul(s, &end, 0);
    if((*s == 0) || (*end != 0) || (l > INT_MAX))
        return -1;
    *value = l;
    return 0;
}

static int str_getenum(const char *s, const char *opt[])
{
    for(int i = 0; opt[i] != NULL; ++i)
        if(!strcasecmp(s, opt[i]))
            return i;
    return -1;
}

static int str_getyesno(const char *s, const char *yes, const char *no)
{
    if (!strcasecmp(s, yes))
        return 1;
    else if (!strcasecmp(s, no))
        return 0;
    return -1;
}

#ifdef _CONF_TEST
static const char *conf_mode_to_str(protocol_version_t mode, const char *fail)
{
    switch (mode)
    {
        case protoSTP:
            return "stp";
        case protoRSTP:
            return "rstp";
        case protoMSTP:
            return "mstp";
    }
    return fail;
}

static const char *conf_p2p_to_str(admin_p2p_t p2p, const char *fail)
{
    switch (p2p)
    {
        case p2pAuto:
            return "auto";
        case p2pForceTrue:
            return "yes";
        case p2pForceFalse:
            return "no";
    }
    return fail;
}
#endif

static int conf_loadfile(struct iobuf *iob, const char *filename)
{
    int fd = open(filename, 0, O_RDONLY);
    if (fd < 0)
        return -1;
    int ret = iobuf_read_from_fd(iob, fd);
    close(fd);
    if (ret < 0)
        return -1;
    return 0;
}

static struct conf_opt *conf_opt_get(const char *name, const struct conf_opt *opts)
{
    for (int pos = 0; opts[pos].name; pos++)
    {
        if (strcasecmp(name, opts[pos].name) == 0)
            return (struct conf_opt *)&opts[pos];
    }

    return NULL;
}

static int conf_split_line(char **argv, int argc_max, char *line)
{
    int argc = 0;
    size_t pos = 0;

    while (argc < argc_max)
    {
        argv[argc] = &line[pos];

        size_t lb = pos;
        for (; line[pos] != 0; pos++)
        {
            if ((line[pos] == 0x09) || (line[pos] == 0x20))
                break;
        }

        size_t le = pos;
        while ((line[pos] == 0x09) || (line[pos] == 0x20))
        {
            pos++;
        }

        line[le] = 0;

        if (le - lb > 0)
            argc++;

        if (line[pos] == 0)
            break;
    }

    line[pos + 1] = 0;

    return argc;
}

static int conf_vids_dec(__u16 *vid2mstid, const char *s, __u16 mstid)
{
    while (*s != 0)
    {
        char *send;
        unsigned long xval;
        int aval;
        int bval = -1;

        xval = strtoul(s, &send, 10);
        aval = (xval <= MAX_VID) ? xval : MAX_VID;

        if (*send == '-')
        {
          send++;
          xval = strtoul(send, &send, 10);
          bval = (xval <= MAX_VID) ? xval : MAX_VID;

          if (aval > bval)
              return -1;
        }

        s = send;

        if (*s == ',')
            s++;
        else if (*s != 0)
            return -1;

        if (bval >= 0)
            for (; aval <= bval; aval++)
                vid2mstid[aval] = mstid;
        else
            vid2mstid[aval] = mstid;
    }

    return 0;
}

#ifdef _CONF_TEST
static int conf_vids_enc(char *out, size_t max_len, __u16 *vid2mstid, __u16 mstid)
{
    int cnt = 0;
    size_t rem_len = max_len - 1;

    for (int pos = 0; pos <= MAX_VID; pos++)
    {
        if (vid2mstid[pos] == mstid)
        {
            int begin = pos;
            int end = begin;
            while (end + 1 <= MAX_VID)
            {
                if (vid2mstid[end + 1] == mstid)
                    end++;
                else
                    break;
            }
            pos = end;

            if (cnt > 0)
            {
                if (rem_len < 1)
                {
                    out[rem_len] = 0;
                    return -1;
                }
                *out = ',';
                out++;
                rem_len--;
            }

            int ret;
            if (begin != end)
            {
                ret = snprintf(out, rem_len + 1, "%d-%d", begin, end);
            }
            else
            {
                ret = snprintf(out, rem_len + 1, "%d", begin);
            }

            if (ret >= rem_len)
            {
                out[max_len - 1] = 0;
                return -1;
            }
            out += ret;
            rem_len -= ret;

            cnt++;
        }
    }

    out[rem_len] = 0;
    return 0;
}
#endif

static int conf_prt_add_mstid(struct conf_prt *cprt, __u16 mstid)
{
    if (mstid == 0)
    {
        return 0;
    }

    for (int pos = 0; pos < cprt->mstids_cnt; pos++)
        if (mstid == cprt->mstids[pos].id)
            return 0;

    if ((cprt->mstids_cnt + 1) * sizeof(struct conf_prt_mstid) > cprt->mstids_sz)
    {
        size_t nsz = (((cprt->mstids_cnt + 1) + (MSTID_PAGE_SIZE - 1))
                      / MSTID_PAGE_SIZE) * MSTID_PAGE_SIZE;
        struct conf_prt_mstid *mstids;
        mstids = realloc(cprt->mstids, nsz);
        if (!mstids)
            return -2;
        cprt->mstids = mstids;
        cprt->mstids_sz = nsz;
    }

    memset(&cprt->mstids[cprt->mstids_cnt], 0, sizeof(struct conf_prt_mstid));
    cprt->mstids[cprt->mstids_cnt].id = mstid;
    cprt->mstids_cnt++;
    return 0;
}

/*****************************************************************************
  OPT Function Prototypes
*****************************************************************************/

#define CONF_FN_OPT_UINT(_fn_name, _tgt_var) \
static int _fn_name(struct conf_ctx *ctx) \
{ \
    unsigned int value; \
    if (str_getuint(ctx->argv[0], &value)) \
    { \
        CTX_ERR(ctx, "Invalid %s value", ctx->optname); \
        return -1; \
    } \
    ctx->_tgt_var = value; \
    ctx->_tgt_var ## _set = true; \
    return 0; \
}

#define CONF_FN_OPT_UINTX(_fn_name, _tgt_var, _max_val) \
static int _fn_name(struct conf_ctx *ctx) \
{ \
    unsigned int value; \
    if (str_getuint(ctx->argv[0], &value)) \
    { \
        CTX_ERR(ctx, "Invalid %s value", ctx->optname); \
        return -1; \
    } \
    if (value > _max_val) \
    { \
        CTX_INF(ctx, "Warning %s %lu, max is %d", ctx->optname, value, \
                     _max_val); \
        value = _max_val; \
    } \
    ctx->_tgt_var = value; \
    ctx->_tgt_var ## _set = true; \
    return 0; \
}

#define CONF_FN_OPT_YESNO(_fn_name, _tgt_var) \
static int _fn_name(struct conf_ctx *ctx) \
{ \
    int value = str_getyesno(ctx->argv[0], "yes", "no"); \
    if (value < 0) \
    { \
        CTX_ERR(ctx, "Invalid %s value '%s'", ctx->optname, ctx->argv[0]); \
        return -1; \
    } \
    ctx->_tgt_var = value; \
    ctx->_tgt_var ## _set = true; \
    return 0; \
}

/*****************************************************************************
  OPT Bridge Functions
*****************************************************************************/


static int conf_opt_br_mode(struct conf_ctx *ctx)
{
    int ret = str_getenum(ctx->argv[0], conf_opt_mode);
    if (ret < 0)
      {
        CTX_ERR(ctx, "Invalid %s value '%s'", ctx->optname, ctx->argv[0]);
        return -1;
      }

    int vals[] = { protoSTP, protoRSTP, protoMSTP };
    ctx->br->mode = vals[ret];
    ctx->br->mode_set = true;
    return 0;
}

CONF_FN_OPT_UINTX(conf_opt_br_max_age, br->max_age, MAX_MAX_AGE);
CONF_FN_OPT_UINTX(conf_opt_br_forward_delay, br->forward_delay, MAX_FORWARD_DELAY);
CONF_FN_OPT_UINTX(conf_opt_br_max_hops, br->max_hops, MAX_HOPS);
CONF_FN_OPT_UINTX(conf_opt_br_hello, br->hello, MAX_HELLO);
CONF_FN_OPT_UINT(conf_opt_br_ageing, br->ageing);
CONF_FN_OPT_UINTX(conf_opt_br_tx_hold_count, br->tx_hold_count, MAX_TX_HOLD_COUNT);

static int conf_opt_br_confid(struct conf_ctx *ctx)
{
    unsigned int rev;
    if (str_getuint(ctx->argv[0], &rev))
    {
        CTX_ERR(ctx, "Invalid %s revision", ctx->optname);
        return -1;
    }
    if (rev > MAX_CONFIG_REV)
    {
        CTX_INF(ctx, "Warning %s revision %lu, max is %d", ctx->optname, rev,
                     MAX_CONFIG_REV);
        rev = MAX_CONFIG_REV;
    }
    size_t nlen = strlen(ctx->argv[1]);
    if (nlen + 1 > CONFIGURATION_NAME_LEN)
    {
        CTX_INF(ctx, "Warning %s name '%s' too long", ctx->optname,
                     ctx->argv[1]);
        nlen = CONFIGURATION_NAME_LEN - 1;
    }

    ctx->br->confid_rev = rev;
    ctx->br->confid_set = true;
    memset(ctx->br->confid_name, 0, sizeof(ctx->br->confid_name));
    memcpy(ctx->br->confid_name, ctx->argv[1], nlen);
    return 0;
}

static int conf_opt_br_mstid(struct conf_ctx *ctx)
{
    struct conf_br *cbr = ctx->br;

    unsigned int value;
    if (str_getuint(ctx->argv[0], &value))
    {
        CTX_ERR(ctx, "Invalid %s value", ctx->optname);
        return -1;
    }
    if (value > MAX_MSTID)
    {
        CTX_INF(ctx, "Warning %s %lu, max is %d", ctx->optname, value,
                     MAX_MSTID);
        value = MAX_MSTID;
    }

    if (value == 0)
    {
        ctx->mstid = 0;
        return 0;
    }

    for (int pos = 0; pos < cbr->mstids_cnt; pos++)
        if (value == cbr->mstids[pos].id)
        {
            cbr->mstids[pos].set = true;
            ctx->mstid = value;
            return 0;
        }

    if ((cbr->mstids_cnt + 1) * sizeof(struct conf_br_mstid) > cbr->mstids_sz)
    {
        size_t nsz = (((cbr->mstids_cnt + 1) + (MSTID_PAGE_SIZE - 1))
                      / MSTID_PAGE_SIZE) * MSTID_PAGE_SIZE;
        struct conf_br_mstid *mstids;
        mstids = realloc(cbr->mstids, nsz);
        if (!mstids)
            return -1;
        cbr->mstids = mstids;
        cbr->mstids_sz = nsz;
    }

    cbr->mstids[cbr->mstids_cnt].id = value;
    cbr->mstids[cbr->mstids_cnt].set = true;
    cbr->mstids_cnt++;
    ctx->mstid = value;
    return 0;
}

static int conf_opt_br_prio(struct conf_ctx *ctx)
{
    struct conf_br *cbr = ctx->br;

    unsigned int value;
    if (str_getuint(ctx->argv[0], &value))
    {
        CTX_ERR(ctx, "Invalid %s value", ctx->optname);
        return -1;
    }
    if (value > MAX_BR_PRIO)
    {
        CTX_INF(ctx, "Warning %s %lu, max is %d", ctx->optname, value,
                     MAX_BR_PRIO);
        value = MAX_BR_PRIO;
    }
    if (value % 4096)
    {
        CTX_INF(ctx, "Warning %s %lu, not multiple of 4096", ctx->optname,
                     value);
    }
    value = (value + 4095) / 4096;

    if (ctx->mstid < 0)
    {
        CTX_INF(ctx, "Ignoring %s, mstid does not exist", ctx->optname);
        return 0;
    }

    if (ctx->mstid == 0)
    {
        cbr->prio = value;
        cbr->prio_set = true;
        return 0;
    }

    for (int pos = 0; pos < cbr->mstids_cnt; pos++)
        if (ctx->mstid == cbr->mstids[pos].id)
        {
            cbr->mstids[pos].prio = value;
            cbr->mstids[pos].prio_set = true;
            return 0;
        }

    CTX_INF(ctx, "Ignoring %s, mstid %lu does not exist", ctx->optname, ctx->mstid);
    return 0;
}

static int conf_opt_br_vids(struct conf_ctx *ctx)
{
    struct conf_br *cbr = ctx->br;

    if (ctx->mstid == 0)
    {
        CTX_INF(ctx, "Warning option %s not available for CIST", ctx->optname);
        return 0;
    }

    for (int pos = 0; pos < cbr->mstids_cnt; pos++)
        if (ctx->mstid == cbr->mstids[pos].id)
        {
            for (int pos = 0; pos < ctx->argc; pos++)
            {
                if (!conf_vids_dec(cbr->vid2mstid, ctx->argv[pos], ctx->mstid))
                    cbr->vid2mstid_set = true;
                else
                    CTX_INF(ctx, "Warning %s value '%s'", ctx->optname,
                                 ctx->argv[pos]);
            }

            return 0;
        }

    CTX_INF(ctx, "Ignoring %s, mstid %lu does not exist", ctx->optname, ctx->mstid);
    return 0;
}

/*****************************************************************************
  OPT Port Functions
*****************************************************************************/

CONF_FN_OPT_YESNO(conf_opt_prt_admin_edge, prt->admin_edge);
CONF_FN_OPT_YESNO(conf_opt_prt_auto_edge, prt->auto_edge);

static int conf_opt_prt_p2p(struct conf_ctx *ctx)
{
    int value = str_getenum(ctx->argv[0], conf_opt_yesnoauto);
    if (value < 0)
    {
        CTX_ERR(ctx, "Invalid %s value '%s'", ctx->optname, ctx->argv[0]);
        return -1;
    }

    int vals[] = { p2pForceFalse, p2pForceTrue, p2pAuto };
    ctx->prt->p2p = vals[value];
    ctx->prt->p2p_set = true;
    return 0;
}

CONF_FN_OPT_YESNO(conf_opt_prt_rest_role, prt->rest_role);
CONF_FN_OPT_YESNO(conf_opt_prt_rest_tcn, prt->rest_tcn);
CONF_FN_OPT_YESNO(conf_opt_prt_bpdu_guard, prt->bpdu_guard);
CONF_FN_OPT_YESNO(conf_opt_prt_network, prt->network);
CONF_FN_OPT_YESNO(conf_opt_prt_dont_txmt, prt->dont_txmt);
CONF_FN_OPT_YESNO(conf_opt_prt_bpdu_filter, prt->bpdu_filter);

static int conf_opt_prt_mstid(struct conf_ctx *ctx)
{
    struct conf_prt *cprt = ctx->prt;

    unsigned int value;
    if (str_getuint(ctx->argv[0], &value))
    {
        CTX_ERR(ctx, "Invalid %s value", ctx->optname);
        return -1;
    }
    if (value > MAX_MSTID)
    {
        CTX_INF(ctx, "Warning %s %lu, max is %d", ctx->optname, value,
                     MAX_MSTID);
        value = MAX_MSTID;
    }

    if (value == 0)
    {
        ctx->mstid = 0;
        return 0;
    }

    for (int pos = 0; pos < cprt->mstids_cnt; pos++)
        if (value == cprt->mstids[pos].id)
        {
            cprt->mstids[pos].set = true;
            ctx->mstid = value;
            return 0;
        }

    ctx->mstid = value;
    CTX_INF(ctx, "Unable to select mstid %d, does not exist on bridge", value);
    return 0;
}

static int conf_opt_prt_prio(struct conf_ctx *ctx)
{
    struct conf_prt *cprt = ctx->prt;

    unsigned int value;
    if (str_getuint(ctx->argv[0], &value))
    {
        CTX_ERR(ctx, "Invalid %s value", ctx->optname);
        return -1;
    }
    if (value > MAX_PRT_PRIO)
    {
        CTX_INF(ctx, "Warning %s %lu, max is %d", ctx->optname, value,
                     MAX_PRT_PRIO);
        value = MAX_PRT_PRIO;
    }
    if (value % 16)
    {
        CTX_INF(ctx, "Warning %s %lu, not multiple of 16", ctx->optname,
                     value);
    }
    value = (value + 15) / 16;

    if (ctx->mstid == 0)
    {
        cprt->prio = value;
        cprt->prio_set = true;
        return 0;
    }

    for (int pos = 0; pos < cprt->mstids_cnt; pos++)
        if (ctx->mstid == cprt->mstids[pos].id)
        {
            cprt->mstids[pos].prio = value;
            cprt->mstids[pos].prio_set = true;
            return 0;
        }

    CTX_INF(ctx, "Ignoring %s, mstid %lu does not exist", ctx->optname, ctx->mstid);
    return -1;
}

static int conf_opt_prt_int_cost(struct conf_ctx *ctx)
{
    struct conf_prt *cprt = ctx->prt;

    unsigned int value;
    if (str_getuint(ctx->argv[0], &value))
    {
        CTX_ERR(ctx, "Invalid %s value", ctx->optname);
        return -1;
    }
    if (value > MAX_COST)
    {
        CTX_INF(ctx, "Warning %s %lu, max is %d", ctx->optname, value,
                     MAX_COST);
        value = MAX_COST;
    }

    if (ctx->mstid == 0)
    {
        cprt->int_cost = value;
        cprt->int_cost_set = true;
        return 0;
    }

    for (int pos = 0; pos < cprt->mstids_cnt; pos++)
        if (ctx->mstid == cprt->mstids[pos].id)
        {
            cprt->mstids[pos].int_cost = value;
            cprt->mstids[pos].int_cost_set = true;
            return 0;
        }

    CTX_INF(ctx, "Ignoring %s, mstid %lu does not exist", ctx->optname, ctx->mstid);
    return -1;
}

static int conf_opt_prt_ext_cost(struct conf_ctx *ctx)
{
    unsigned int value;
    if (str_getuint(ctx->argv[0], &value))
    {
        CTX_ERR(ctx, "Invalid %s value", ctx->optname);
        return -1;
    }

    if (value > MAX_COST)
    {
        CTX_INF(ctx, "Warning %s %lu, max is %d", ctx->optname, value,
                     MAX_COST);
        value = MAX_COST;
    }
    ctx->prt->ext_cost = value;
    ctx->prt->ext_cost_set = true;
    return 0;
}

/*****************************************************************************
  Configuration main section
*****************************************************************************/

static void conf_br_init(struct conf_br *cbr)
{
    memset(cbr, 0, sizeof(struct conf_br));
}

static void conf_prt_init(struct conf_prt *cprt)
{
    memset(cprt, 0, sizeof(struct conf_prt));
}

static void conf_br_cleanup(struct conf_br *cbr)
{
    if (cbr->mstids)
    {
        free(cbr->mstids);
        cbr->mstids = NULL;
        cbr->mstids_sz = 0;
        cbr->mstids_cnt = 0;
    }
}

static void conf_prt_cleanup(struct conf_prt *cprt)
{
    if (cprt->mstids)
    {
        free(cprt->mstids);
        cprt->mstids = NULL;
        cprt->mstids_sz = 0;
        cprt->mstids_cnt = 0;
    }
}

#ifdef _CONF_TEST
static void conf_br_print(FILE *stream, struct conf_br *cbr)
{
    char sbuf[1024];

    if (cbr->mode_set)
        fprintf(stream, "mode %s\n", conf_mode_to_str(cbr->mode, "error"));
    if (cbr->max_age_set)
        fprintf(stream, "max-age %d\n", cbr->max_age);
    if (cbr->forward_delay_set)
        fprintf(stream, "forward-delay %d\n", cbr->forward_delay);
    if (cbr->max_hops_set)
        fprintf(stream, "max-hops %d\n", cbr->max_hops);
    if (cbr->hello_set)
        fprintf(stream, "hello %d\n", cbr->hello);
    if (cbr->ageing_set)
        fprintf(stream, "ageing %d\n", cbr->ageing);
    if (cbr->tx_hold_count_set)
        fprintf(stream, "tx_hold_count %d\n", cbr->tx_hold_count);
    if (cbr->confid_set)
    {
        fprintf(stream, "confid %d %.*s\n", cbr->confid_rev,
                         CONFIGURATION_NAME_LEN, cbr->confid_name);
    }
    if (cbr->prio_set)
        fprintf(stream, "prio %d\n", cbr->prio * 4096);

    for (int pos = 0; pos < cbr->mstids_cnt; pos++)
    {
        fprintf(stream, "\nmstid %d\n", cbr->mstids[pos].id);
        if (cbr->mstids[pos].prio_set)
            fprintf(stream, "	prio %d\n", cbr->mstids[pos].prio * 4096);
        if (cbr->vid2mstid_set)
            if (!conf_vids_enc(sbuf, 1024, cbr->vid2mstid, cbr->mstids[pos].id))
                fprintf(stream, "	vids %s\n", sbuf);
    }
}

static void conf_prt_print(FILE *stream, struct conf_prt *cprt)
{
    if (cprt->admin_edge_set)
        fprintf(stream, "admin-edge %s\n", conf_opt_yesno[cprt->admin_edge]);
    if (cprt->auto_edge_set)
        fprintf(stream, "auto-edge %s\n", conf_opt_yesno[cprt->auto_edge]);
    if (cprt->p2p_set)
        fprintf(stream, "p2p %s\n", conf_p2p_to_str(cprt->p2p, "error"));
    if (cprt->rest_role_set)
        fprintf(stream, "rest-role %s\n", conf_opt_yesno[cprt->rest_role]);
    if (cprt->rest_tcn_set)
        fprintf(stream, "rest-tcn %s\n", conf_opt_yesno[cprt->rest_tcn]);
    if (cprt->bpdu_guard_set)
        fprintf(stream, "bpdu-guard %s\n", conf_opt_yesno[cprt->bpdu_guard]);
    if (cprt->network_set)
        fprintf(stream, "network %s\n", conf_opt_yesno[cprt->network]);
    if (cprt->dont_txmt_set)
        fprintf(stream, "dont-txmt %s\n", conf_opt_yesno[cprt->dont_txmt]);
    if (cprt->bpdu_filter_set)
        fprintf(stream, "bpdu-filter %s\n", conf_opt_yesno[cprt->bpdu_filter]);
    if (cprt->prio_set)
        fprintf(stream, "prio %d\n", cprt->prio * 16);
    if (cprt->int_cost_set)
        fprintf(stream, "int-cost %d\n", cprt->int_cost);
    if (cprt->ext_cost_set)
        fprintf(stream, "ext-cost %d\n", cprt->ext_cost);

    for (int pos = 0; pos < cprt->mstids_cnt; pos++)
    {
        fprintf(stream, "\nmstid %d\n", cprt->mstids[pos].id);
        if (cprt->mstids[pos].prio_set)
            fprintf(stream, "	prio %d\n", cprt->mstids[pos].prio * 16);
        if (cprt->mstids[pos].int_cost_set)
            fprintf(stream, "	int-cost %d\n", cprt->mstids[pos].int_cost);
    }
}
#endif

int conf_if_load(struct conf_ctx *ctx, struct iobuf *iob, const struct conf_opt *opts)
{
    int fnret = 0;
    char *line = NULL;
    size_t line_size = 0;

    for (ctx->line = 1;; ctx->line++)
    {
        char *begin;
        int len = iobuf_readcleanline(iob, &begin);

        if (len < 1)
            break;

        len--;

        for (; len > 0; begin++, len--)
        {
            if ((*begin != 0x09) && (*begin != 0x20))
                break;
        }

        if (len == 0)
            continue;
        if (*begin == '#')
            continue;

        if (len + 2 > line_size)
        {
            line_size = (((len + 2) + (LINE_PAGE_SIZE - 1))
                         / LINE_PAGE_SIZE) * LINE_PAGE_SIZE;
            char *new_line = realloc(line, line_size);
            if (!new_line)
            {
                fnret = -2;
                break;
            }
            line = new_line;
        }

        char *argv[8];

        memcpy(line, begin, len);
        line[len] = 0;
        line[len + 1] = 0;
        int argc = conf_split_line((char **)&argv, 8, line);

        struct conf_opt *opt = conf_opt_get(argv[0], opts);
        if (opt)
        {
            argc--;

            if (opt->argc_min > argc)
            {
                CTX_ERR(ctx, "Too few arguments %d for '%s', min %d required",
                             argc, argv[0], opt->argc_min);
            }
            else if ((opt->argc_max != 0) && (opt->argc_max < argc))
            {
                CTX_ERR(ctx, "Too much arguments %d for '%s', max %d allowed",
                             argc, argv[0], opt->argc_max);
            }
            else
            {
                ctx->argv = &argv[1];
                ctx->argc = argc;
                ctx->optname = opt->name;
                int ret = opt->func(ctx);
                if (ret < -1)
                {
                    fnret = ret;
                    break;
                }
            }
        }
        else
        {
            CTX_ERR(ctx, "Unknown option '%s'", argv[0]);
        }

    }

    free(line);
    return fnret;
}

static void mstpd_conf_apply_br(bridge_t *br, struct conf_br *cbr)
{
    CIST_BridgeConfig ccfg;
    bool ccfg_apply = false;

    memset(&ccfg, 0, sizeof(ccfg));

    if (cbr->mode_set)
    {
        ccfg.protocol_version = cbr->mode;
        ccfg.set_protocol_version = true;
        ccfg_apply = true;
    }

    if (cbr->max_age_set)
    {
        ccfg.bridge_max_age = cbr->max_age;
        ccfg.set_bridge_max_age = true;
        ccfg_apply = true;
    }

    if (cbr->forward_delay_set)
    {
        ccfg.bridge_forward_delay = cbr->forward_delay;
        ccfg.set_bridge_forward_delay = true;
        ccfg_apply = true;
    }

    if (cbr->max_hops_set)
    {
        ccfg.max_hops = cbr->max_hops;
        ccfg.set_max_hops = true;
        ccfg_apply = true;
    }

    if (cbr->hello_set)
    {
        ccfg.bridge_hello_time = cbr->hello;
        ccfg.set_bridge_hello_time = true;
        ccfg_apply = true;
    }

    if (cbr->ageing_set)
    {
        ccfg.bridge_ageing_time = cbr->ageing;
        ccfg.set_bridge_ageing_time = true;
        ccfg_apply = true;
    }

    if (cbr->tx_hold_count_set)
    {
        ccfg.tx_hold_count = cbr->tx_hold_count;
        ccfg.set_tx_hold_count = true;
        ccfg_apply = true;
    }

    if (ccfg_apply)
        MSTP_IN_set_cist_bridge_config(br, &ccfg);

    if (cbr->confid_set)
        MSTP_IN_set_mst_config_id(br, cbr->confid_rev, cbr->confid_name);

    if (cbr->prio_set)
        MSTP_IN_set_msti_bridge_config(GET_CIST_TREE(br), cbr->prio * 4096);

    for (int pos = 0; pos < cbr->mstids_cnt; pos++)
    {
        tree_t *tree = MSTP_IN_create_msti(br, cbr->mstids[pos].id);
        if (tree)
        {
            if (cbr->mstids[pos].prio_set)
                MSTP_IN_set_msti_bridge_config(tree, cbr->mstids[pos].prio * 4096);
        }
    }

    if (cbr->vid2mstid_set)
        MSTP_IN_set_all_vids2mstids(br, cbr->vid2mstid);
}

static void mstpd_conf_prepare_prt(port_t *prt, struct conf_prt *cprt)
{
    bridge_t *br = prt->bridge;
    tree_t *tree;

    list_for_each_entry(tree, &br->trees, bridge_list)
        if (tree->MSTID != 0)
            conf_prt_add_mstid(cprt, __be16_to_cpu(tree->MSTID));
}

static void mstpd_conf_apply_prt(port_t *prt, struct conf_prt *cprt)
{
    CIST_PortConfig ccfg;
    bool cfg_apply = false;

    memset(&ccfg, 0, sizeof(ccfg));

    if (cprt->admin_edge_set)
    {
        ccfg.admin_edge_port = cprt->admin_edge;
        ccfg.set_admin_edge_port = true;
        cfg_apply = true;
    }

    if (cprt->auto_edge_set)
    {
        ccfg.auto_edge_port = cprt->auto_edge;
        ccfg.set_auto_edge_port = true;
        cfg_apply = true;
    }

    if (cprt->p2p_set)
    {
        ccfg.admin_p2p = cprt->p2p;
        ccfg.set_admin_p2p = true;
        cfg_apply = true;
    }

    if (cprt->rest_role_set)
    {
        ccfg.restricted_role = cprt->rest_role;
        ccfg.set_restricted_role = true;
        cfg_apply = true;
    }

    if (cprt->rest_tcn_set)
    {
        ccfg.restricted_tcn = cprt->rest_tcn;
        ccfg.set_restricted_tcn = true;
        cfg_apply = true;
    }

    if (cprt->bpdu_guard_set)
    {
        ccfg.bpdu_guard_port = cprt->bpdu_guard;
        ccfg.set_bpdu_guard_port = true;
        cfg_apply = true;
    }

    if (cprt->network_set)
    {
        ccfg.network_port = cprt->network;
        ccfg.set_network_port = true;
        cfg_apply = true;
    }

    if (cprt->dont_txmt_set)
    {
        ccfg.dont_txmt = cprt->dont_txmt;
        ccfg.set_dont_txmt = true;
        cfg_apply = true;
    }

    if (cprt->bpdu_filter_set)
    {
        ccfg.bpdu_filter_port = cprt->bpdu_filter;
        ccfg.set_bpdu_filter_port = true;
        cfg_apply = true;
    }

    if (cprt->ext_cost_set)
    {
        ccfg.admin_external_port_path_cost = cprt->ext_cost;
        ccfg.set_admin_external_port_path_cost = true;
        cfg_apply = true;
    }

    if (cfg_apply)
    {
        MSTP_IN_set_cist_port_config(prt, &ccfg);
        cfg_apply = false;
    }

    MSTI_PortConfig mcfg;
    memset(&mcfg, 0, sizeof(mcfg));

    if (cprt->prio_set)
    {
        mcfg.port_priority = cprt->prio * 16;
        mcfg.set_port_priority = true;
        cfg_apply = true;
    }

    if (cprt->int_cost_set)
    {
        mcfg.admin_internal_port_path_cost = cprt->int_cost;
        mcfg.set_admin_internal_port_path_cost = true;
        cfg_apply = true;
    }

    if (cfg_apply)
    {
        MSTP_IN_set_msti_port_config(GET_CIST_PTP_FROM_PORT(prt), &mcfg);
        cfg_apply = false;
    }

    for (int pos = 0; pos < cprt->mstids_cnt; pos++)
    {
        memset(&mcfg, 0, sizeof(mcfg));

        if (cprt->mstids[pos].prio_set)
        {
            mcfg.port_priority = cprt->mstids[pos].prio * 16;
            mcfg.set_port_priority = true;
            cfg_apply = true;
        }

        if (cprt->mstids[pos].int_cost_set)
        {
            mcfg.admin_internal_port_path_cost = cprt->mstids[pos].int_cost;
            mcfg.set_admin_internal_port_path_cost = true;
            cfg_apply = true;
        }

        if (cfg_apply)
        {
            per_tree_port_t *ptp;
            __be16 MSTID = __cpu_to_be16(cprt->mstids[pos].id);

            list_for_each_entry(ptp, &prt->trees, port_list)
                if (ptp->MSTID == MSTID)
                {
                    MSTP_IN_set_msti_port_config(ptp, &mcfg);
                    break;
                }

            cfg_apply = false;
        }
    }
}

bool mstpd_conf_exist_br(const char *br_name)
{
    char filename[128];

    snprintf(filename, sizeof(filename), MSTPD_CONFIG_DIR "/%s.conf",
             br_name);

    return (access(filename, R_OK) == 0);
}

bool mstpd_conf_load_br(bridge_t *br)
{
    char filename[128];
    struct iobuf iob;
    struct conf_br cbr;
    struct conf_ctx ctx;

    snprintf(filename, sizeof(filename), MSTPD_CONFIG_DIR "/%s.conf",
             br->sysdeps.name);

    if (access(filename, R_OK) != 0)
    {
        INFO("%s: Missing config file %s", br->sysdeps.name, filename);
        return true;
    }

    ctx.cif = (struct conf_if *)&cbr;
    ctx.mstid = 0;
    ctx.argv = NULL;
    ctx.argc = 0;

    conf_br_init(&cbr);

    iobuf_init(&iob);
    int ret = conf_loadfile(&iob, filename);
    if (ret < 0)
    {
        iobuf_cleanup(&iob);
        LOG("%s: Unable to load config file %s", br->sysdeps.name, filename);
        return false;
    }

    ctx.filename = filename + strlen(MSTPD_CONFIG_DIR);
    if (ctx.filename)
        ctx.filename++;
    else
        ctx.filename = filename;

    ret = conf_if_load(&ctx, &iob, conf_opts_br);
    iobuf_cleanup(&iob);
    if (ret >= 0)
        mstpd_conf_apply_br(br, &cbr);
    else
    {
        ERROR("%s: Unable to process config file %s", br->sysdeps.name, filename);
        ret = -1;
    }

    conf_br_cleanup(&cbr);
    return (ret == 0);
}

bool mstpd_conf_load_prt(port_t *prt)
{
    bridge_t *br = prt->bridge;
    char filename[128];
    struct iobuf iob;
    struct conf_prt cprt;
    struct conf_ctx ctx;

    snprintf(filename, sizeof(filename), MSTPD_CONFIG_DIR "/%s/%s.conf",
             br->sysdeps.name, prt->sysdeps.name);

    if (access(filename, R_OK) != 0)
    {
        INFO("%s: Missing config file %s", prt->sysdeps.name, filename);
        return true;
    }

    ctx.cif = (struct conf_if *)&cprt;
    ctx.mstid = 0;
    ctx.argv = NULL;
    ctx.argc = 0;

    conf_prt_init(&cprt);

    iobuf_init(&iob);
    int ret = conf_loadfile(&iob, filename);
    if (ret < 0)
    {
        iobuf_cleanup(&iob);
        LOG("%s: Unable to load config file %s", prt->sysdeps.name, filename);
        return false;
    }

    ctx.filename = filename + strlen(MSTPD_CONFIG_DIR);
    if (ctx.filename)
        ctx.filename++;
    else
        ctx.filename = filename;

    mstpd_conf_prepare_prt(prt, &cprt);

    ret = conf_if_load(&ctx, &iob, conf_opts_prt);
    iobuf_cleanup(&iob);
    if (ret >= 0)
        mstpd_conf_apply_prt(prt, &cprt);
    else
    {
        ERROR("%s: Unable to process config file %s", prt->sysdeps.name, filename);
        ret = -1;
    }

    conf_prt_cleanup(&cprt);
    return (ret == 0);
}

//-------------------------------------------
// TESTING TESTING TESTING
//-------------------------------------------

#ifdef _CONF_TEST
static void test_br(const char *filename)
{
    struct iobuf iob;
    struct conf_br cbr;
    struct conf_ctx ctx;

    if (access(filename, R_OK) != 0)
    {
        LOG("Missing bridge config file %s", filename);
        return;
    }

    ctx.cif = (struct conf_if *)&cbr;
    ctx.mstid = 0;
    ctx.argv = NULL;
    ctx.argc = 0;

    conf_br_init(&cbr);

    iobuf_init(&iob);
    int ret = conf_loadfile(&iob, filename);
    if (ret < 0)
    {
        iobuf_cleanup(&iob);
        ERROR("Unable to load bridge config file %s", filename);
        return;
    }

    ctx.filename = strrchr(filename, '/');
    if (ctx.filename)
        ctx.filename++;
    else
        ctx.filename = filename;

    ret = conf_if_load(&ctx, &iob, conf_opts_br);
    iobuf_cleanup(&iob);

    if (ret < 0)
    {
        ERROR("ERROR, SOMEWHERE!\n");
    }
    else
    {
        conf_br_print(stderr, &cbr);
    }

    conf_br_cleanup(&cbr);
}

static void test_prt(const char *filename)
{
    struct iobuf iob;
    struct conf_prt cprt;
    struct conf_ctx ctx;

    if (access(filename, R_OK) != 0)
    {
        LOG("Missing port config file %s", filename);
        return;
    }

    ctx.cif = (struct conf_if *)&cprt;
    ctx.mstid = 0;
    ctx.argv = NULL;
    ctx.argc = 0;

    conf_prt_init(&cprt);

    iobuf_init(&iob);
    int ret = conf_loadfile(&iob, filename);
    if (ret < 0)
    {
        iobuf_cleanup(&iob);
        ERROR("Unable to load bridge config file %s", filename);
        return;
    }

    ctx.filename = strrchr(filename, '/');
    if (ctx.filename)
        ctx.filename++;
    else
        ctx.filename = filename;

    conf_prt_add_mstid(&cprt, 1);

    ret = conf_if_load(&ctx, &iob, conf_opts_prt);
    iobuf_cleanup(&iob);

    if (ret < 0)
    {
        fprintf(stderr, "ERROR, SOMEWHERE!\n");
    }
    else
    {
        conf_prt_print(stderr, &cprt);
    }

    conf_prt_cleanup(&cprt);
}

int main()
{
    fprintf(stderr, "Testing BR:\n");
    test_br("./conf/swbr0.conf");

    fprintf(stderr, "Testing PRT:\n");
    test_prt("./conf/swp1.conf");

    return 0;
}
#endif
