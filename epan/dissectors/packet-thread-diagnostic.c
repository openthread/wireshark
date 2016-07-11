/* packet-thread-diagnostic.c
 * Routines for Thread TLV packet dissection
 *
 * Robert Cragie <robert.cragie@arm.com>
 *
 * $Id: packet-thread-diagnostic.c $
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
void proto_register_thread_dg(void);
void proto_reg_handoff_thread_dg(void);

#define THREAD_DG_TLV_LENGTH_ESC  0xFF

static int proto_thread_dg = -1;

static int hf_thread_dg_tlv = -1;
static int hf_thread_dg_tlv_type = -1;
static int hf_thread_dg_tlv_length8 = -1;
static int hf_thread_dg_tlv_length16 = -1;
static int hf_thread_dg_tlv_general = -1;
static int hf_thread_dg_tlv_unknown = -1;

#if 0
/**** TBC ****/
static int hf_thread_dg_tlv_source_addr = -1;
static int hf_thread_dg_tlv_mode_device_type = -1;
static int hf_thread_dg_tlv_mode_idle_rx = -1;
static int hf_thread_dg_tlv_mode_sec_data_req = -1;
static int hf_thread_dg_tlv_mode_nwk_data = -1;
static int hf_thread_dg_tlv_timeout = -1;
static int hf_thread_dg_tlv_lqi_c = -1;
static int hf_thread_dg_tlv_lqi_size = -1;
static int hf_thread_dg_tlv_neighbor = -1;
static int hf_thread_dg_tlv_neighbor_flagI = -1;
static int hf_thread_dg_tlv_neighbor_flagO = -1;
static int hf_thread_dg_tlv_neighbor_flagP = -1;
static int hf_thread_dg_tlv_neighbor_idr = -1;
static int hf_thread_dg_tlv_neighbor_addr = -1;
static int hf_thread_dg_tlv_network_param_id = -1;
static int hf_thread_dg_tlv_network_delay = -1;
static int hf_thread_dg_tlv_network_channel = -1;
static int hf_thread_dg_tlv_network_pan_id = -1;
static int hf_thread_dg_tlv_network_pmt_join = -1;
static int hf_thread_dg_tlv_network_bcn_payload = -1;
static int hf_thread_dg_tlv_network_unknown = -1;
static int hf_thread_dg_tlv_mle_frm_cntr = -1;
static int hf_thread_dg_tlv_route_tbl_id_seq = -1;
static int hf_thread_dg_tlv_route_tbl_id_mask = -1;
static int hf_thread_dg_tlv_route_tbl_entry = -1;
static int hf_thread_dg_tlv_route_tbl_nbr_out = -1;
static int hf_thread_dg_tlv_route_tbl_nbr_in = -1;
static int hf_thread_dg_tlv_route_tbl_cost = -1;
static int hf_thread_dg_tlv_route_tbl_unknown = -1;
static int hf_thread_dg_tlv_addr_16 = -1;
static int hf_thread_dg_tlv_leader_data_partition_id = -1;
static int hf_thread_dg_tlv_leader_data_weighting = -1;
static int hf_thread_dg_tlv_leader_data_version = -1;
static int hf_thread_dg_tlv_leader_data_stable_version = -1;
static int hf_thread_dg_tlv_leader_data_router_id = -1;
static int hf_thread_dg_tlv_network_data = -1;
static int hf_thread_dg_tlv_scan_mask_r = -1;
static int hf_thread_dg_tlv_scan_mask_e = -1;
static int hf_thread_dg_tlv_conn_max_child_cnt = -1;
static int hf_thread_dg_tlv_conn_child_cnt = -1;
static int hf_thread_dg_tlv_conn_lq3 = -1;
static int hf_thread_dg_tlv_conn_lq2 = -1;
static int hf_thread_dg_tlv_conn_lq1 = -1;
static int hf_thread_dg_tlv_conn_leader_cost = -1;
static int hf_thread_dg_tlv_conn_id_seq = -1;
static int hf_thread_dg_tlv_link_margin = -1;
static int hf_thread_dg_tlv_status = -1;
static int hf_thread_dg_tlv_version = -1;
static int hf_thread_dg_tlv_addr_reg_entry = -1;
static int hf_thread_dg_tlv_addr_reg_iid_type = -1;
static int hf_thread_dg_tlv_addr_reg_cid = -1;
static int hf_thread_dg_tlv_addr_reg_iid = -1;
static int hf_thread_dg_tlv_addr_reg_ipv6 = -1;
static int hf_thread_dg_tlv_hold_time = -1;
#endif

static gint ett_thread_dg = -1;
static gint ett_thread_dg_tlv = -1;

static expert_field ei_thread_dg_tlv_length_failed = EI_INIT;
static expert_field ei_thread_dg_len_size_mismatch = EI_INIT;

static dissector_handle_t thread_dg_handle;

/* Network Layer (Address) mirrors */
#define THREAD_DG_TLV_EXT_MAC_ADDR          0 /* As THREAD_ADDRESS_TLV_EXT_MAC_ADDR */
/* MLE mirrors */
#define THREAD_DG_TLV_ADDRESS16             1 /* As MLE_TLV_ADDRESS16 */
#define THREAD_DG_TLV_MODE                  2 /* As MLE_TLV_MODE */
#define THREAD_DG_TLV_TIMEOUT               3 /* As MLE_TLV_TIMEOUT */
#define THREAD_DG_TLV_CONNECTIVITY          4 /* As MLE_TLV_CONNECTIVITY */
#define THREAD_DG_TLV_ROUTE64               5 /* As MLE_TLV_ROUTE64 */
#define THREAD_DG_TLV_LEADER_DATA           6 /* As MLE_TLV_LEADER_DATA */
#define THREAD_DG_TLV_NETWORK_DATA          7 /* As MLE_TLV_NETWORK_DATA */
/* Statistics */
#define THREAD_DG_TLV_IPV6_ADDR_LIST        8
#define THREAD_DG_TLV_MAC_COUNTERS          9
/* Others */
#define THREAD_DG_TLV_BATTERY_LEVEL         14
#define THREAD_DG_TLV_VOLTAGE               15
#define THREAD_DG_TLV_CHILD_TABLE           16
#define THREAD_DG_TLV_CHANNEL_PAGES         17
#define THREAD_DG_TLV_TYPE_LIST             18
#define THREAD_DG_TLV_UNKNOWN               255

static const value_string thread_dg_tlv_vals[] = {
/* Network Layer (Address) mirrors */
{ THREAD_DG_TLV_EXT_MAC_ADDR,          "Extended MAC Address" },
/* MLE mirrors */
{ THREAD_DG_TLV_ADDRESS16,             "Address16" },
{ THREAD_DG_TLV_MODE,                  "Mode" },
{ THREAD_DG_TLV_TIMEOUT,               "Timeout" },
{ THREAD_DG_TLV_CONNECTIVITY,          "Connectivity" },
{ THREAD_DG_TLV_ROUTE64,               "Route64" },
{ THREAD_DG_TLV_LEADER_DATA,           "Leader Data" },
{ THREAD_DG_TLV_NETWORK_DATA,          "Network Data" },
/* Statistics */
{ THREAD_DG_TLV_IPV6_ADDR_LIST,        "IPv6 Address List" },
{ THREAD_DG_TLV_MAC_COUNTERS,          "MAC Counters" },
/* Others */
{ THREAD_DG_TLV_BATTERY_LEVEL,         "Battery level (%)" },
{ THREAD_DG_TLV_VOLTAGE,               "Voltage (mV)" },
{ THREAD_DG_TLV_CHILD_TABLE,           "Child Table" },
{ THREAD_DG_TLV_CHANNEL_PAGES,         "Channel Pages" },
{ THREAD_DG_TLV_TYPE_LIST,             "Type List" },
{ THREAD_DG_TLV_UNKNOWN,               "Unknown" }
};

typedef enum {
    DG_LENGTH8 = 0,
    DG_LENGTH16
} dg_length_e;

static int
dissect_thread_dg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *volatile proto_root = NULL;
    proto_tree  *volatile thread_dg_tree = NULL;
    proto_tree  *tlv_tree;
    guint       offset;
    proto_item  *ti;
    guint8      tlv_type;
    guint16     tlv_len;
    dg_length_e tlv_dg_len;
   
    (void)pinfo; /* Prevent warning/error */

    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_thread_dg, tvb, 0, tvb_reported_length(tvb), "Thread Diagnostic");
        thread_dg_tree = proto_item_add_subtree(proto_root, ett_thread_dg);
    }

    offset = 0;
    
    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {
 
        /* Get the type and length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_type = tvb_get_guint8(tvb, offset);
        tlv_len = (guint16)tvb_get_guint8(tvb, offset + 1);
        
        /* TODO: need to make sure this applies to all Diagnostic TLVs */
        if (THREAD_DG_TLV_LENGTH_ESC == tlv_len) {
            /* 16-bit length field */
            tlv_len = tvb_get_ntohs(tvb, offset + 2);
            tlv_dg_len = DG_LENGTH16;
        } else {
            tlv_dg_len = DG_LENGTH8;
        }

        /* Create the tree */
        ti = proto_tree_add_item(thread_dg_tree, hf_thread_dg_tlv, tvb, offset, tlv_len, FALSE);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_dg_tlv);
        
        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_type, tvb, offset, 1, FALSE);
        offset++;
    
        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s", val_to_str(tlv_type, thread_dg_tlv_vals, "Unknown (%d)"));

        /* Length */
        switch (tlv_dg_len) {
            case DG_LENGTH8:
                proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_length8, tvb, offset, 1, FALSE);
                offset++;
                break;
            case DG_LENGTH16:
                proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_length16, tvb, offset + 1, 2, FALSE);
                offset += 3; /* Including escape byte */
                break;
            default:
                break;
        }
        
        switch(tlv_type) {
            case THREAD_DG_TLV_TYPE_LIST:
                {
                    int i;
                    
                    proto_item_append_text(ti, ")");

                    for (i = 0; i < tlv_len; i++) {
                        proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_type, tvb, offset, 1, FALSE);
                        offset++;
                    }
                }
                break;
                
            case THREAD_DG_TLV_EXT_MAC_ADDR:
            case THREAD_DG_TLV_ADDRESS16:
            case THREAD_DG_TLV_MODE:
            case THREAD_DG_TLV_TIMEOUT:
            case THREAD_DG_TLV_CONNECTIVITY:
            case THREAD_DG_TLV_ROUTE64:
            case THREAD_DG_TLV_LEADER_DATA:
            case THREAD_DG_TLV_NETWORK_DATA:
            case THREAD_DG_TLV_IPV6_ADDR_LIST:
            /* Counters */
            case THREAD_DG_TLV_MAC_COUNTERS:
            case THREAD_DG_TLV_BATTERY_LEVEL:
            case THREAD_DG_TLV_VOLTAGE:
            case THREAD_DG_TLV_CHILD_TABLE:
            case THREAD_DG_TLV_CHANNEL_PAGES:
                proto_item_append_text(ti, ")");
                proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_general, tvb, offset, tlv_len, FALSE);
                offset += tlv_len;           
                break;
                
            default:
                proto_item_append_text(ti, ")");
                proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_unknown, tvb, offset, tlv_len, FALSE);
                offset += tlv_len;           
        }        
    }
    return tvb_captured_length(tvb);
}

void
proto_register_thread_dg(void)
{
  static hf_register_info hf[] = {
    
    /* Generic TLV */
    { &hf_thread_dg_tlv,
      { "TLV",
        "thread_diagnostic.tlv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Type-Length-Value",
        HFILL
      }
    },
        
    { &hf_thread_dg_tlv_type,
      { "Type",
        "thread_diagnostic.tlv.type",
        FT_UINT8, BASE_DEC, VALS(thread_dg_tlv_vals), 0x0,
        "Type of value",
        HFILL
      }
    },

    { &hf_thread_dg_tlv_length8,
      { "Length",
        "thread_diagnostic.tlv.len8",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of value (8-bit)",
        HFILL
      }
    },
    
    { &hf_thread_dg_tlv_length16,
      { "Length",
        "thread_diagnostic.tlv.len16",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of value (16-bit)",
        HFILL
      }
    },
    
    { &hf_thread_dg_tlv_general,
      { "General",
        "thread_diagnostic.tlv.general",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "General TLV, raw value",
        HFILL
      }
    },
    
    { &hf_thread_dg_tlv_unknown,
      { "Unknown",
        "thread_diagnostic.tlv.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown TLV, raw value",
        HFILL
      }
    }
  };
  
  static gint *ett[] = {
    &ett_thread_dg,
    &ett_thread_dg_tlv,
  };

  static ei_register_info ei[] = {
    { &ei_thread_dg_tlv_length_failed, { "thread_diagnostic.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
    { &ei_thread_dg_len_size_mismatch, { "thread_diagnostic.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
  };

  expert_module_t* expert_thread_dg;

  proto_thread_dg = proto_register_protocol("Thread Diagnostics", "Thread Diagnostics", "thread_diagnostic");
  proto_register_field_array(proto_thread_dg, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_thread_dg = expert_register_protocol(proto_thread_dg);
  expert_register_field_array(expert_thread_dg, ei, array_length(ei));

  register_dissector("thread_diagnostic", dissect_thread_dg, proto_thread_dg);
}

void
proto_reg_handoff_thread_dg(void)
{
  static gboolean thread_dg_initialized = FALSE;

  if (!thread_dg_initialized) {
    thread_dg_handle = find_dissector("thread_diagnostic");
    thread_dg_initialized = TRUE;
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
