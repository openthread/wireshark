/* packet-thread-address.c
 * Routines for Thread Network Data packet dissection
 *
 * Robert Cragie <robert.cragie@arm.com>
 *
 * $Id: packet-thread-address.c $
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

/* Forward declarations */
void proto_register_thread_diagnostic(void);
void proto_reg_handoff_thread_diagnostic(void);

static int proto_thread_diagnostic = -1;

static int hf_thread_diagnostic_tlv = -1;
static int hf_thread_diagnostic_tlv_type = -1;
static int hf_thread_diagnostic_tlv_length = -1;
static int hf_thread_diagnostic_tlv_unknown = -1;

static gint ett_thread_diagnostic = -1;
static gint ett_thread_diagnostic_tlv = -1;

static expert_field ei_thread_diagnostic_tlv_length_failed = EI_INIT;
static expert_field ei_thread_diagnostic_len_size_mismatch = EI_INIT;

static dissector_handle_t thread_diagnostic_handle;

#define THREAD_DIAGNOSTIC_TLV_UNKNOWN                  255

static const value_string thread_diagnostic_tlv_vals[] = {
{ THREAD_DIAGNOSTIC_TLV_UNKNOWN,               "Unknown" }
};

static void
dissect_thread_diagnostic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *volatile proto_root = NULL;
    proto_tree  *volatile thread_diagnostic_tree = NULL;
    proto_tree  *tlv_tree;
    guint       offset;
    proto_item  *ti;
    guint8      tlv_type, tlv_len;
   
    (void)pinfo; /* Prevent warning/error */

    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_thread_diagnostic, tvb, 0, tvb_reported_length(tvb), "Thread Diagnostic");
        thread_diagnostic_tree = proto_item_add_subtree(proto_root, ett_thread_diagnostic);
    }

    offset = 0;
    
    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {
 
        /* Get the length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_len = tvb_get_guint8(tvb, offset + 1);
 
        ti = proto_tree_add_item(thread_diagnostic_tree, hf_thread_diagnostic_tlv, tvb, offset, tlv_len, FALSE);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_diagnostic_tlv);
        
        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_diagnostic_tlv_type, tvb, offset, 1, FALSE);
        tlv_type = tvb_get_guint8(tvb, offset);
        offset++;
    
        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s", val_to_str(tlv_type, thread_diagnostic_tlv_vals, "Unknown (%d)"));

        /* Length */
        proto_tree_add_item(tlv_tree, hf_thread_diagnostic_tlv_length, tvb, offset, 1, FALSE);
        offset++;
        
        switch(tlv_type) {
            default:                
                proto_item_append_text(ti, ")");
                proto_tree_add_item(tlv_tree, hf_thread_diagnostic_tlv_unknown, tvb, offset, tlv_len, FALSE);
                offset += tlv_len;           
        }        
    }
}

void
proto_register_thread_diagnostic(void)
{
  static hf_register_info hf[] = {
    
    /* Generic TLV */
    { &hf_thread_diagnostic_tlv,
      { "TLV",
        "thread_diagnostic.tlv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Type-Length-Value",
        HFILL
      }
    },
        
    { &hf_thread_diagnostic_tlv_type,
      { "Type",
        "thread_diagnostic.tlv.type",
        FT_UINT8, BASE_DEC, VALS(thread_diagnostic_tlv_vals), 0x0,
        "Type of value",
        HFILL
      }
    },

    { &hf_thread_diagnostic_tlv_length,
      { "Length",
        "thread_diagnostic.tlv.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of value",
        HFILL
      }
    },
    
    { &hf_thread_diagnostic_tlv_unknown,
      { "Unknown",
        "thread_diagnostic.tlv.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown TLV, raw value",
        HFILL
      }
    }
  };
  
  static gint *ett[] = {
    &ett_thread_diagnostic,
    &ett_thread_diagnostic_tlv,
  };

  static ei_register_info ei[] = {
    { &ei_thread_diagnostic_tlv_length_failed, { "thread_diagnostic.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
    { &ei_thread_diagnostic_len_size_mismatch, { "thread_diagnostic.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
  };

  expert_module_t* expert_thread_diagnostic;

  proto_thread_diagnostic = proto_register_protocol("Thread Diagnostics", "Thread Diagnostics", "thread_diagnostic");
  proto_register_field_array(proto_thread_diagnostic, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_thread_diagnostic = expert_register_protocol(proto_thread_diagnostic);
  expert_register_field_array(expert_thread_diagnostic, ei, array_length(ei));

  register_dissector("thread_diagnostic", dissect_thread_diagnostic, proto_thread_diagnostic);
}

void
proto_reg_handoff_thread_diagnostic(void)
{
  static gboolean thread_diagnostic_initialized = FALSE;

  if (!thread_diagnostic_initialized) {
    thread_diagnostic_handle = find_dissector("thread_diagnostic");
    thread_diagnostic_initialized = TRUE;
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
