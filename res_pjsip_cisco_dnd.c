/* Copyright (C) 2024 Timon Schneider info@timon-schneider.com
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * res_pjsip_cisco_dnd.c
 *
 * Intercepts the "Event: presence" PUBLISH that a Cisco CP-8xxx sends when
 * the user toggles the Do-Not-Disturb softkey, and mirrors that state onto
 * the FreePBX side:
 *
 *   Phone       SIP                         Module
 *   -----------------------------------------------------------------
 *   DND on  -> PUBLISH  <ce:dnd/>        -> AstDB  DND/<ext> = "YES"
 *                                        -> devstate Custom:DND<ext> BUSY
 *                                        -> 200 OK Expires=big, SIP-ETag
 *   DND off -> PUBLISH  <ce:available/>  -> AstDB  DND/<ext> removed
 *                                        -> devstate Custom:DND<ext> NOT_INUSE
 *                                        -> 200 OK Expires=big, SIP-ETag
 *
 * The AstDB write matches exactly what FreePBX's Core DND feature code
 * (*78 / *79) does, so the Cisco soft key becomes equivalent to the
 * standard FreePBX DND toggle: Follow-Me, CF, queues, everything reads
 * this same key.  The devstate fire lights BLF keys wired to
 * "hint => *78<ext>,Custom:DND<ext>".
 *
 * --- Extension resolution ---------------------------------------------
 * Cisco phones register with their MAC address as the SIP From user
 * (e.g. From: <sip:cc5a535fc4b7@pbx>;tag=...), but — luckily — they
 * still put the real extension number in the Contact header
 * (Contact: <sip:200@192.168.1.14:5060;transport=udp>;...).
 *
 * Resolution order (first non-empty, non-MAC-looking value wins):
 *   1. set_var CISCO_DND_EXTEN=<ext> on the identified PJSIP endpoint.
 *      Operator override — wins over everything.  Configure in
 *      /etc/asterisk/pjsip.endpoint_custom_post.conf like:
 *          [wohnzimmer](+)
 *          set_var = CISCO_DND_EXTEN=200
 *   2. Contact header user part.
 *   3. From header user part.
 *
 * A value that looks like a bare 12-hex-char MAC is rejected as an
 * extension (we will NOT write AstDB DND/<mac>), because no FreePBX
 * feature reads that key and it would silently do nothing.  In that
 * case the 200 OK is still sent (so the phone doesn't storm us) and
 * a WARNING is logged telling the operator to add a CISCO_DND_EXTEN
 * set_var.
 */

/* Required for externally-compiled Asterisk modules */
#define AST_MODULE_SELF_SYM __local_ast_module_self

/*** MODULEINFO
    <depend>pjproject</depend>
    <depend>res_pjsip</depend>
    <support_level>extended</support_level>
 ***/

#include "asterisk.h"
#include "asterisk/module.h"
#include "asterisk/res_pjsip.h"
#include "asterisk/astdb.h"
#include "asterisk/devicestate.h"
#include "asterisk/strings.h"
#include "asterisk/utils.h"
#include "asterisk/logger.h"
#include "asterisk/astobj2.h"
#include "asterisk/lock.h"

#include <pjsip.h>

/* Monotonic counter — a freshly-minted SIP-ETag on every 200 OK.  We do
 * not track state; we always accept SIP-If-Match unconditionally. */
static volatile int cisco_dnd_etag_seq;

/* ---------- helpers --------------------------------------------------- */

/* Return the user part of a pjsip URI-ish header into *out.  Returns
 * 0 on success, -1 if the URI isn't sip:/sips: or has no user part.
 * Accepts anything that pjsip_uri_get_uri() resolves (From, To, Contact). */
static int uri_user(void *hdr_uri, char *out, size_t sz)
{
    pjsip_uri *uri;
    pjsip_sip_uri *sip_uri;

    if (!hdr_uri) return -1;
    uri = (pjsip_uri *)pjsip_uri_get_uri(hdr_uri);
    if (!uri) return -1;
    if (!PJSIP_URI_SCHEME_IS_SIP(uri) && !PJSIP_URI_SCHEME_IS_SIPS(uri))
        return -1;

    sip_uri = (pjsip_sip_uri *)uri;
    if (sip_uri->user.slen <= 0) return -1;

    {
        int ulen = (int)sip_uri->user.slen;
        if (ulen >= (int)sz) ulen = sz - 1;
        memcpy(out, sip_uri->user.ptr, ulen);
        out[ulen] = '\0';
    }
    return 0;
}

static int from_user(pjsip_from_hdr *from, char *out, size_t sz)
{
    return uri_user(from ? from->uri : NULL, out, sz);
}

/* Contact: <sip:<user>@<host>...>.  Returns the Contact URI user into *out.
 * Returns 0 on success, -1 if no Contact / no sip URI / no user part. */
static int contact_user(pjsip_rx_data *rdata, char *out, size_t sz)
{
    pjsip_contact_hdr *ct;

    ct = (pjsip_contact_hdr *)pjsip_msg_find_hdr(rdata->msg_info.msg,
        PJSIP_H_CONTACT, NULL);
    if (!ct || ct->star || !ct->uri) return -1;
    return uri_user(ct->uri, out, sz);
}

/* A Cisco phone's MAC user part is always exactly 12 lowercase hex
 * characters (e.g. "cc5a535fc4b7").  Detect and reject this so it doesn't
 * get treated as an extension number. */
static int looks_like_mac(const char *s)
{
    int i;
    if (!s) return 0;
    for (i = 0; i < 12; i++) {
        char c = s[i];
        if (c == '\0') return 0;
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return s[12] == '\0';
}

/* Look up "CISCO_DND_EXTEN" in the endpoint's set_var list.  Returns
 * 1 if found, 0 otherwise. */
static int endpoint_setvar(struct ast_sip_endpoint *ep, const char *name,
    char *out, size_t sz)
{
    struct ast_variable *v;

    if (!ep) return 0;
    for (v = ep->channel_vars; v; v = v->next) {
        if (!strcmp(v->name, name) && v->value && v->value[0]) {
            ast_copy_string(out, v->value, sz);
            return 1;
        }
    }
    return 0;
}

/* ---------- DND state application ------------------------------------- */

static void cisco_dnd_apply(const char *exten, int dnd_on)
{
    char devname[128];

    if (!exten || exten[0] == '\0') {
        ast_log(LOG_WARNING, "CiscoDND: empty extension — cannot apply\n");
        return;
    }

    if (dnd_on) {
        if (ast_db_put("DND", exten, "YES")) {
            ast_log(LOG_WARNING,
                "CiscoDND: ast_db_put(DND/%s=YES) failed\n", exten);
        }
    } else {
        /* delete returns non-zero if the key wasn't present — harmless. */
        ast_db_del("DND", exten);
    }

    snprintf(devname, sizeof(devname), "Custom:DND%s", exten);
    ast_devstate_changed(
        dnd_on ? AST_DEVICE_BUSY : AST_DEVICE_NOT_INUSE,
        AST_DEVSTATE_CACHABLE, "%s", devname);

    ast_log(LOG_NOTICE,
        "CiscoDND: extension %s DND %s (AstDB %s, devstate %s=%s)\n",
        exten,
        dnd_on ? "ON" : "OFF",
        dnd_on ? "DND/<ext>=YES" : "DND/<ext> cleared",
        devname,
        dnd_on ? "BUSY" : "NOT_INUSE");
}

/* ---------- 200 OK with Expires + SIP-ETag ---------------------------- */

static void cisco_dnd_send_200(pjsip_rx_data *rdata)
{
    pjsip_endpoint *endpt = ast_sip_get_pjsip_endpoint();
    pjsip_tx_data *tdata;
    pj_status_t status;
    pj_str_t hname, hval;
    char etag_buf[64];
    int etag;

    status = pjsip_endpt_create_response(endpt, rdata, 200, NULL, &tdata);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoDND: could not create 200 response: %d\n", status);
        return;
    }

    /* Expires: 2147483647 — mirrors CUCM, effectively "forever". */
    {
        pjsip_expires_hdr *exp = pjsip_expires_hdr_create(tdata->pool,
            2147483647);
        pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)exp);
    }

    /* SIP-ETag: fresh on every response.  Because we don't track state we
     * accept any SIP-If-Match on updates (phone usually sends the ETag we
     * gave it on the previous 200). */
    etag = ast_atomic_fetchadd_int(&cisco_dnd_etag_seq, 1);
    snprintf(etag_buf, sizeof(etag_buf), "%d%ld",
        etag & 0x7fffffff, (long)time(NULL));
    hname = pj_str("SIP-ETag");
    hval.ptr  = etag_buf;
    hval.slen = (pj_ssize_t)strlen(etag_buf);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    pjsip_endpt_send_response2(endpt, rdata, tdata, NULL, NULL);
}

/* ---------- PJSIP receive callback ------------------------------------ */

static pj_bool_t cisco_dnd_on_rx_request(pjsip_rx_data *rdata)
{
    pjsip_msg *msg = rdata->msg_info.msg;
    char body[8192];
    int blen;
    int dnd_on;
    const char *dnd_marker, *avail_marker;
    char exten[64] = "";
    struct ast_sip_endpoint *ep = NULL;

    /* PUBLISH only.  We deliberately compare the method name string
     * instead of a pjsip_publish_method constant — pjsip's PUBLISH method
     * symbol lives in pjsip-simple (event framework), which external
     * modules don't necessarily link against. */
    if (pj_strcmp2(&msg->line.req.method.name, "PUBLISH") != 0)
        return PJ_FALSE;

    /* Content-Type: application/pidf+xml — anything else is not ours. */
    if (!msg->body || !msg->body->data || !msg->body->len)
        return PJ_FALSE;
    if (pj_stricmp2(&msg->body->content_type.type,    "application") != 0 ||
        pj_stricmp2(&msg->body->content_type.subtype, "pidf+xml")    != 0)
        return PJ_FALSE;

    blen = (int)msg->body->len < (int)(sizeof(body) - 1)
           ? (int)msg->body->len : (int)(sizeof(body) - 1);
    memcpy(body, msg->body->data, blen);
    body[blen] = '\0';

    /* Detect the Cisco proprietary activity markers.  Anything else (a
     * plain presence PUBLISH carrying only <basic>open</basic>, for
     * example) we let the normal pjsip stack handle. */
    dnd_marker   = strstr(body, "<ce:dnd");
    avail_marker = strstr(body, "<ce:available");
    if (!dnd_marker && !avail_marker) {
        return PJ_FALSE;
    }
    dnd_on = dnd_marker != NULL;

    /* Resolve the extension.  Order of precedence:
     *   1. CISCO_DND_EXTEN set_var on the identified pjsip endpoint
     *      (operator override, wins over everything).
     *   2. Contact header user part.  Cisco phones put their extension
     *      there (Contact: <sip:200@...>), even when they use their MAC
     *      in From (From: <sip:cc5a535fc4b7@...>).
     *   3. From header user part, but only if it doesn't look like a
     *      12-char MAC.
     * If we land on something that looks like a MAC we log and still
     * 200 — the phone would otherwise retry-storm us — but we do NOT
     * touch AstDB / devstate, to avoid writing bogus DND/<mac> keys
     * that no FreePBX dialplan will ever read. */
    ep = ast_sip_identify_endpoint(rdata);
    if (ep) {
        endpoint_setvar(ep, "CISCO_DND_EXTEN", exten, sizeof(exten));
    }
    if (exten[0] == '\0') {
        char cu[64] = "";
        if (contact_user(rdata, cu, sizeof(cu)) == 0 && !looks_like_mac(cu)) {
            ast_copy_string(exten, cu, sizeof(exten));
        }
    }
    if (exten[0] == '\0') {
        char fu[64] = "";
        if (from_user(rdata->msg_info.from, fu, sizeof(fu)) == 0 &&
            !looks_like_mac(fu)) {
            ast_copy_string(exten, fu, sizeof(exten));
        }
    }
    if (exten[0] == '\0') {
        ast_log(LOG_WARNING,
            "CiscoDND: could not determine extension from PUBLISH "
            "(Contact/From look like MAC and no CISCO_DND_EXTEN set_var). "
            "Configure:\n"
            "  [<endpoint-id>](+)\n"
            "  set_var = CISCO_DND_EXTEN=<extension>\n"
            "in pjsip.endpoint_custom_post.conf and 'pjsip reload'.\n");
        if (ep) ao2_cleanup(ep);
        /* Still 200 so the phone doesn't retry-storm us. */
        cisco_dnd_send_200(rdata);
        return PJ_TRUE;
    }

    if (ep) {
        ast_log(LOG_NOTICE,
            "CiscoDND: PUBLISH from endpoint '%s' → extension '%s' (DND %s)\n",
            ast_sorcery_object_get_id(ep), exten, dnd_on ? "ON" : "OFF");
        ao2_cleanup(ep);
    } else {
        ast_log(LOG_NOTICE,
            "CiscoDND: PUBLISH (unidentified) → extension '%s' (DND %s)\n",
            exten, dnd_on ? "ON" : "OFF");
    }

    cisco_dnd_apply(exten, dnd_on);
    cisco_dnd_send_200(rdata);

    return PJ_TRUE;
}

/* ---------- module registration --------------------------------------- */

static pjsip_module cisco_dnd_pjsip_module = {
    .name     = { "mod-cisco-dnd", 14 },
    /*
     * CRITICAL: we have to sit BEFORE Asterisk's pjsip distributor,
     * which runs at PJSIP_MOD_PRIORITY_TSX_LAYER - 6 (= 10) and is the
     * module that performs endpoint identification + digest auth on
     * incoming out-of-dialog requests.
     *
     * A Cisco CP-8xxx sends its DND PUBLISH out-of-dialog with
     *   From: <sip:<MAC>@pbx>
     * and the phone's DND softkey uses WHATEVER credentials it was
     * provisioned with — which, in real deployments, often do not line
     * up with the FreePBX PJSIP endpoint the phone is registered under
     * (the endpoint is usually named after the extension, not the MAC).
     * The distributor therefore 401s the PUBLISH, the phone retries
     * with a fresh nonce, loops forever, and eventually locks up.
     *
     * Registering at TRANSPORT_LAYER + 1 means our on_rx_request runs
     * immediately after the parser, before the distributor ever gets
     * the chance to dispatch/auth the request.  We answer 200 OK and
     * return PJ_TRUE, which short-circuits the rest of the chain.
     *
     * We still only consume PUBLISHes that carry a Cisco pidf body
     * with <ce:dnd/> or <ce:available/>.  Anything else returns
     * PJ_FALSE and continues normally through the distributor.
     */
    .priority = PJSIP_MOD_PRIORITY_TRANSPORT_LAYER + 1,
    .on_rx_request = cisco_dnd_on_rx_request,
};

static int load_module(void)
{
    if (ast_sip_register_service(&cisco_dnd_pjsip_module)) {
        ast_log(LOG_ERROR, "CiscoDND: failed to register PJSIP service\n");
        return AST_MODULE_LOAD_DECLINE;
    }
    ast_log(LOG_NOTICE, "CiscoDND: Cisco DND module loaded\n");
    return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
    ast_sip_unregister_service(&cisco_dnd_pjsip_module);
    return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT,
    "Cisco x-cisco-remotecc DND Handler",
    .support_level = AST_MODULE_SUPPORT_EXTENDED,
    .load   = load_module,
    .unload = unload_module,
    .requires = "res_pjsip",
);
