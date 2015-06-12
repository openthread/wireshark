/* packet-thread-coap.c
 * Routines for Thread CoAP packet dissection
 *
 * Robert Cragie <robert.cragie@arm.com>
 *
 * $Id: packet-thread-coap.c $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

//#ifdef HAVE_CONFIG_H
#include "config.h"
//#endif

#include <glib.h>
#include <stdlib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>
#include <epan/range.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include "packet-coap.h"

/* Forward declarations */
void proto_register_thread_coap(void);
void proto_reg_handoff_thread_coap(void);

static gboolean thread_coap_is_octet_stream = FALSE;

static int proto_thread_coap = -1;

static dissector_handle_t thread_coap_handle;
static dissector_handle_t thread_nwd_handle;
static dissector_handle_t thread_meshcop_handle;
static dissector_handle_t thread_address_handle;
static dissector_handle_t thread_diagnostic_handle;

typedef enum {
    THREAD_COAP_URI_THREAD,     /* "..." */
    THREAD_COAP_URI_NWD,        /* "/n/..." */
    THREAD_COAP_URI_MESHCOP,    /* "/c/..." */
    THREAD_COAP_URI_ADDRESS,    /* "/a/..."  */
    THREAD_COAP_URI_DIAGNOSTIC  /* "/d/..."  */
} thread_coap_uri_type;

static void
dissect_thread_coap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    coap_info           *coinfo;
    gchar               *tok, *uri;
    thread_coap_uri_type uri_type;
    
    /* Obtain the CoAP info */
    coinfo = (coap_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_get_id_by_filter_name("coap"), 0);
    uri = (gchar *)wmem_strbuf_get_str(coinfo->uri_str_strbuf);
    
    uri_type = THREAD_COAP_URI_THREAD;
    for (tok = strtok(uri, "/"); tok; tok = strtok(NULL, "/")) {
        if (THREAD_COAP_URI_THREAD == uri_type) {
            if (strcmp ("n", tok) == 0) {
                uri_type = THREAD_COAP_URI_NWD;
            }
            else if (strcmp ("c", tok) == 0) {
                uri_type = THREAD_COAP_URI_MESHCOP;
            }
            else if (strcmp ("a", tok) == 0) {
                uri_type = THREAD_COAP_URI_ADDRESS;
            }
            else if (strcmp ("d", tok) == 0) {
                uri_type = THREAD_COAP_URI_DIAGNOSTIC;
            }
            break; /* Done at the second token */
        }
    }
    
    if (THREAD_COAP_URI_THREAD == uri_type) {
        /* Not enough to go on */
        return;
    }

    switch (uri_type) {
    case THREAD_COAP_URI_NWD:
        /* No need to create a subset as we are dissecting the tvb as it is */
        call_dissector(thread_nwd_handle, tvb, pinfo, tree);
        break;
    case THREAD_COAP_URI_MESHCOP:
        call_dissector(thread_meshcop_handle, tvb, pinfo, tree);
        break;
    case THREAD_COAP_URI_ADDRESS:
        call_dissector(thread_address_handle, tvb, pinfo, tree);
        break;
    case THREAD_COAP_URI_DIAGNOSTIC:
        call_dissector(thread_diagnostic_handle, tvb, pinfo, tree);
        break;
    default:
        break;
    }
}

void
proto_register_thread_coap(void)
{
  module_t *thread_coap_module;

  proto_thread_coap = proto_register_protocol("Thread CoAP", "Thread CoAP", "thread_coap");
  register_dissector("thread_coap", dissect_thread_coap, proto_thread_coap);
  
  /* TODO - need to somehow splice it into CoAP - media type? */
  //range_convert_str(&global_mle_port_range, UDP_PORT_MLE_RANGE, MAX_UDP_PORT);

  thread_coap_module = prefs_register_protocol(proto_thread_coap, proto_reg_handoff_thread_coap);
  prefs_register_bool_preference(thread_coap_module, "thread_coap",
                                 "Decode CoAP for Thread",
                                 "Try to decode CoAP for Thread",
                                 &thread_coap_is_octet_stream);
}

void
proto_reg_handoff_thread_coap(void)
{
  static gboolean thread_coap_initialized = FALSE;

  if (!thread_coap_initialized) {
    thread_coap_handle = find_dissector("thread_coap");
    thread_nwd_handle = find_dissector("thread_nwd");
    thread_meshcop_handle = find_dissector("thread_meshcop");
    thread_address_handle = find_dissector("thread_address");
    thread_diagnostic_handle = find_dissector("thread_diagnostic");
    thread_coap_initialized = TRUE;
  }
  
  if (thread_coap_is_octet_stream) {
    dissector_add_string("media_type", "application/octet-stream", thread_coap_handle);
  } else {
    dissector_delete_string("media_type", "application/octet-stream", thread_coap_handle);
  }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab
 * :indentSize=2:tabSize=8:noTabs=true:
 */
