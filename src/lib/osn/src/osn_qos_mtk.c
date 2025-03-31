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

#include "log.h"
#include "memutil.h"
#include "osn_qos.h"
#include "execsh.h"
#include "const.h"
#include "lnx_qos.h"

#define MTK_QOS_RATE_DEFAULT    2500000     /**< Default rate in kbit/s, used to reset queue speeds */
#define MTK_QOS_MARK_BASE    0x44000000
/*
 * There are actually 128 hw queues:
 * Qid 0-15 are assigned for the MTK pqqq and OpenSync mac/app prioritization feature.
 * Qid 16-47 are assigned for QoS. It can be extended to 127.
 * Qid 48-127 are reserved.
 */
#define MTK_QOS_MAX_QUEUES  32          /**< Maximum number of queues available */
#define MTK_QOS_QUEUES_ID_OFFSET  16    /**< QID + OFFSET = actual HW QID */

struct osn_qos
{
    int         *q_id;              /* Array of IDs used by this object */
    int         *q_id_e;            /* End of array */
    lnx_qos_t   oq_lnx;
};

struct mtk_qos_queue
{
    int         qq_min_rate;        /**< Queue min rate in kbit/s */
    int         qq_max_rate;        /**< Queue max rate in kbit/s */
    char        *qq_tag;            /**< Queue tag */
    int         qq_refcnt;          /**< Queue reference count, 0 if unused */
};

static struct mtk_qos_queue mtk_qos_queue_list[MTK_QOS_MAX_QUEUES];

static bool mtk_qos_queue_reset(int queue_id);
static bool mtk_qos_queue_set(int queue_id, int min_rate, int max_rate);
static int mtk_qos_id_get(const char *tag);
static void mtk_qos_id_put(int id);

static char mtk_qos_queue_config[] = _S(
        qid="$1";
        maxrate="$2";
        minrate="$3";
        schid=1;
        minebl=1;
        maxebl=1;
        weight=4;
        resv=4;
        echo "$schid" "$minebl" "$minrate" "$maxebl" "$maxrate" \
             "$weight" "$resv" > /sys/kernel/debug/mtk_ppe/qdma_txq"$qid");
/*
 * ===========================================================================
 *  OSN API implementation
 * ===========================================================================
 */
osn_qos_t* osn_qos_new(const char *ifname)
{
    osn_qos_t *self;

    self = CALLOC(1, sizeof(*self));
    if (!lnx_qos_init(&self->oq_lnx, ifname))
    {
        FREE(self);
        return NULL;
    }
    return self;
}

void osn_qos_del(osn_qos_t *self)
{
    int *qp;

    for (qp = self->q_id; qp < self->q_id_e; qp++)
    {
        mtk_qos_id_put(*qp);
    }

    FREE(self->q_id);

    lnx_qos_fini(&self->oq_lnx);
    FREE(self);
}

bool osn_qos_apply(osn_qos_t *self)
{
    int *qp;

    bool retval = true;

    /*
     * Apply QoS configuration to system
     */
    for (qp = self->q_id; qp < self->q_id_e; qp++)
    {
        if (!mtk_qos_queue_set(
                *qp,
                mtk_qos_queue_list[*qp].qq_min_rate,
                mtk_qos_queue_list[*qp].qq_max_rate))
        {
            /* mtk_qos_queue_set() reported the error already */
            retval = false;
            break;
        }
    }
    retval = lnx_qos_apply(&self->oq_lnx);
    return retval;
}

bool osn_qos_begin(osn_qos_t *self, struct osn_qos_other_config *other_config)
{
    return lnx_qos_begin(&self->oq_lnx, other_config);
}

bool osn_qos_end(osn_qos_t *self)
{
    return lnx_qos_end(&self->oq_lnx);
}

bool osn_qos_queue_begin(
        osn_qos_t *self,
        int priority,
        int bandwidth,
        int bandwidth_ceil,
        const char *tag,
        const struct osn_qos_other_config *other_config,
        struct osn_qos_queue_status *qqs)
{
    int qid;
    int *qp;

    memset(qqs, 0, sizeof(*qqs));

    qid = mtk_qos_id_get(tag);
    if (qid < 0)
    {
        LOG(ERR, "mtk_qos: All queues are full.");
        return false;
    }

    /* Append the queue id to the list for this object */
    qp = MEM_APPEND(&self->q_id, &self->q_id_e, sizeof(*qp));
    *qp = qid;

    if (bandwidth_ceil > 0)
    {
        mtk_qos_queue_list[qid].qq_max_rate = bandwidth_ceil;
        mtk_qos_queue_list[qid].qq_min_rate = bandwidth;
    }
    else
    {
        mtk_qos_queue_list[qid].qq_max_rate = bandwidth;
        mtk_qos_queue_list[qid].qq_min_rate = 0;
    }

    /* Calculate the MARK for this DPI */
    qqs->qqs_fwmark = MTK_QOS_MARK_BASE | qid;

    return lnx_qos_queue_begin(
        &self->oq_lnx,
        priority,
        bandwidth,
        bandwidth_ceil,
        tag,
        other_config,
        qqs);
}

bool osn_qos_queue_end(osn_qos_t *self)
{
    return lnx_qos_queue_end(&self->oq_lnx);
}

/*
 * ===========================================================================
 *  MTK backend
 * ===========================================================================
 */
static bool mtk_qos_queue_set(int queue_id, int min_rate, int max_rate)
{
    int rc;
    char sqid[C_INT32_LEN];
    char sminrate[C_INT32_LEN];
    char smaxrate[C_INT32_LEN];

    LOG(INFO, "mtk_qos: queue[%d]: Applying settings min_rate=%d, max_rate=%d",
            queue_id, min_rate, max_rate);

    snprintf(sqid, sizeof(sqid), "%d", queue_id + MTK_QOS_QUEUES_ID_OFFSET);
    snprintf(sminrate, sizeof(sminrate), "%d", min_rate);
    snprintf(smaxrate, sizeof(smaxrate), "%d", max_rate);
    rc = execsh_log(
            LOG_SEVERITY_DEBUG,
            mtk_qos_queue_config,
            sqid,
            smaxrate,
            sminrate);
    if (rc != 0)
    {
        LOG(ERR, "mtk_qos: queue[%d]: Error during configuration.", queue_id);
        return false;
    }

    return true;
}

static bool mtk_qos_queue_reset(int queue_id)
{
    return mtk_qos_queue_set(queue_id, 0, MTK_QOS_RATE_DEFAULT);
}

static int mtk_qos_id_get(const char *tag)
{
    int qid;

    /* Check if there's a queue with a matching tag */
    if (tag != NULL)
    {
        for (qid = 0; qid < MTK_QOS_MAX_QUEUES; qid++)
        {
            if (mtk_qos_queue_list[qid].qq_tag != NULL &&
                    strcmp(mtk_qos_queue_list[qid].qq_tag, tag) == 0)
            {
                break;
            }
        }

        if (qid < MTK_QOS_MAX_QUEUES)
        {
            /* The tag was found return this index */
            mtk_qos_queue_list[qid].qq_refcnt++;
            return qid;
        }
    }

    /* Find first empty queue */
    for (qid = 0; qid < MTK_QOS_MAX_QUEUES; qid++)
    {
        if (mtk_qos_queue_list[qid].qq_refcnt == 0) break;
    }

    if (qid >= MTK_QOS_MAX_QUEUES)
    {
        return -1;
    }

    mtk_qos_queue_list[qid].qq_refcnt = 1;
    if (tag != NULL)
    {
        mtk_qos_queue_list[qid].qq_tag = strdup(tag);
    }

    return qid;
}

static void mtk_qos_id_put(int qid)
{
    if (qid >= MTK_QOS_MAX_QUEUES) return;

    if (mtk_qos_queue_list[qid].qq_refcnt-- > 1)
    {
        return;
    }

    if (!mtk_qos_queue_reset(qid))
    {
        LOG(WARN, "mtk_qos: Unable to reset queue %d.", qid);
    }

    FREE(mtk_qos_queue_list[qid].qq_tag);
    mtk_qos_queue_list[qid].qq_tag = NULL;
}

bool osn_qos_notify_event_set(osn_qos_t *self, osn_qos_event_fn_t *event_fn_cb)
{
    (void)self;
    (void)event_fn_cb;

    /*
     * This implementation backend does not support QoS event reporting.
     * (There is no need for event reporting on this platform-specific implementation.)
     */
    return false;
}

bool osn_qos_is_qdisc_based(osn_qos_t *self)
{
    return false;
}
