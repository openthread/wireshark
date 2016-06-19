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
void proto_register_thread_address(void);
void proto_reg_handoff_thread_address(void);

static int proto_thread_address = -1;

static int hf_thread_address_tlv = -1;
static int hf_thread_address_tlv_type = -1;
static int hf_thread_address_tlv_length = -1;
static int hf_thread_address_tlv_unknown = -1;
static int hf_thread_address_tlv_sub_tlvs = -1;

/* Target EID TLV fields */
static int hf_thread_address_tlv_target_eid = -1;

/* Ext. MAC address TLV fields */
static int hf_thread_address_tlv_ext_mac_addr = -1;

/* RLOC16 TLV fields */
static int hf_thread_address_tlv_rloc16 = -1;

/* Mesh Local IID TLV fields */
static int hf_thread_address_tlv_ml_eid = -1;

/* Status TLV fields */
static int hf_thread_address_tlv_status = -1;

/* Attached time TLV fields */
static int hf_thread_address_tlv_attached_time = -1;

/* Last transaction time TLV fields */
static int hf_thread_address_tlv_last_transaction_time = -1;

/* Router Mask TLV fields */
static int hf_thread_address_tlv_router_mask_id_seq = -1;
static int hf_thread_address_tlv_router_mask_assigned = -1;

/* ND option fields */
static int hf_thread_address_tlv_nd_option = -1;

/* ND data fields */
static int hf_thread_address_tlv_nd_data = -1;

static gint ett_thread_address = -1;
static gint ett_thread_address_tlv = -1;

static expert_field ei_thread_address_tlv_length_failed = EI_INIT;
static expert_field ei_thread_address_len_size_mismatch = EI_INIT;

static dissector_handle_t thread_nwd_handle;

#define THREAD_ADDRESS_TLV_TARGET_EID               0
#define THREAD_ADDRESS_TLV_EXT_MAC_ADDR             1
#define THREAD_ADDRESS_TLV_RLOC16                   2
#define THREAD_ADDRESS_TLV_ML_EID                   3
#define THREAD_ADDRESS_TLV_STATUS                   4
/* Gap */
#define THREAD_ADDRESS_TLV_LAST_TRANSACTION_TIME    6
#define THREAD_ADDRESS_TLV_ROUTER_MASK              7
#define THREAD_ADDRESS_TLV_ND_OPTION                8
#define THREAD_ADDRESS_TLV_ND_DATA                  9
#define THREAD_ADDRESS_TLV_THREAD_NETWORK_DATA      10

static const value_string thread_address_tlv_vals[] = {
{ THREAD_ADDRESS_TLV_TARGET_EID,            "Target EID" },
{ THREAD_ADDRESS_TLV_EXT_MAC_ADDR,          "Extended MAC Address" },
{ THREAD_ADDRESS_TLV_RLOC16,                "RLOC16" },
{ THREAD_ADDRESS_TLV_ML_EID,                "ML-EID" },
{ THREAD_ADDRESS_TLV_STATUS,                "Status" },
/* Gap */
{ THREAD_ADDRESS_TLV_LAST_TRANSACTION_TIME, "Last Transaction Time" },
{ THREAD_ADDRESS_TLV_ND_OPTION,             "ND Option" },
{ THREAD_ADDRESS_TLV_ND_DATA,               "ND Data" },
{ THREAD_ADDRESS_TLV_THREAD_NETWORK_DATA,   "Thread Network Data" }
};

static const value_string thread_address_tlv_status_vals[] = {
{ 0, "Success" },
{ 1, "No Address Available" },
};

static int
dissect_thread_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *volatile proto_root = NULL;
    proto_tree  *volatile thread_address_tree = NULL;
    proto_tree  *tlv_tree;
    tvbuff_t    *sub_tvb;
    guint       offset;
    proto_item  *ti;
    guint8      tlv_type, tlv_len;
   
    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_thread_address, tvb, 0, tvb_reported_length(tvb), "Thread Address");
        thread_address_tree = proto_item_add_subtree(proto_root, ett_thread_address);
    }

    offset = 0;
    
    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {
 
        /* Get the length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_len = tvb_get_guint8(tvb, offset + 1);
 
        ti = proto_tree_add_item(thread_address_tree, hf_thread_address_tlv, tvb, offset, tlv_len, FALSE);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_address_tlv);
        
        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_type, tvb, offset, 1, FALSE);
        tlv_type = tvb_get_guint8(tvb, offset);
        offset++;
    
        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s", val_to_str(tlv_type, thread_address_tlv_vals, "Unknown (%d)"));

        /* Length */
        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_length, tvb, offset, 1, FALSE);
        offset++;
        
        switch(tlv_type) {
            case THREAD_ADDRESS_TLV_TARGET_EID:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Target EID */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_target_eid, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
            
            case THREAD_ADDRESS_TLV_EXT_MAC_ADDR:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Extended MAC address */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_ext_mac_addr, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_ADDRESS_TLV_RLOC16:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Mesh Locator */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_rloc16, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_ADDRESS_TLV_ML_EID:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* ML IID */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_ml_eid, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_ADDRESS_TLV_STATUS:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Status */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_status, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_ADDRESS_TLV_LAST_TRANSACTION_TIME:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 4) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Last transaction time */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_last_transaction_time, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_ADDRESS_TLV_ROUTER_MASK:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 9) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, FALSE);
                        offset += tlv_len;
                    } else {
                        /* Router Mask */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_router_mask_id_seq, tvb, offset, 1, FALSE);
                        offset++;

                        /* 
                         * | | | | | | | | | | |1|1|1|1|1|1|...|6|
                         * |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|...|3|
                         * ---------------------------------------
                         * |1|0|1|1|1|0|0|0|1|1|0|0|0|1|0|1|...
                         *
                         * is sent as 0xb8, 0xc5
                         * and represents table entry for routers 0, 2, 3, 4, 8, 9, 13, 15...
                         */
                    
                        /* Just show the string of octets - best representation for a bit mask */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_router_mask_assigned, tvb, offset, 8, FALSE);
                        offset += 8;
                    }
                }
                break;

            case THREAD_ADDRESS_TLV_ND_OPTION:
                /* Just show the data */
                proto_tree_add_item(tlv_tree, hf_thread_address_tlv_nd_option, tvb, offset, tlv_len, FALSE);
                offset += tlv_len;
                break;

            case THREAD_ADDRESS_TLV_ND_DATA:
                /* Just show the data. Note there is no icmpv6 options dissector so would have to copy it */
                proto_tree_add_item(tlv_tree, hf_thread_address_tlv_nd_data, tvb, offset, tlv_len, FALSE);
                offset += tlv_len;
                break;
                
            case THREAD_ADDRESS_TLV_THREAD_NETWORK_DATA:
                proto_item_append_text(ti, ")");
                if (tlv_len > 0) {
                    sub_tvb = tvb_new_subset_length(tvb, offset, tlv_len);
                    call_dissector(thread_nwd_handle, sub_tvb, pinfo, tlv_tree);
                }
                offset += tlv_len;
                break;
                
            default:                
                proto_item_append_text(ti, ")");
                proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, FALSE);
                offset += tlv_len;           
        }        
    }
    return tvb_captured_length(tvb);
}

void
proto_register_thread_address(void)
{
  static hf_register_info hf[] = {
    
    /* Generic TLV */
    { &hf_thread_address_tlv,
      { "TLV",
        "thread_address.tlv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Type-Length-Value",
        HFILL
      }
    },
        
    { &hf_thread_address_tlv_type,
      { "Type",
        "thread_address.tlv.type",
        FT_UINT8, BASE_DEC, VALS(thread_address_tlv_vals), 0x0,
        "Type of value",
        HFILL
      }
    },

    { &hf_thread_address_tlv_length,
      { "Length",
        "thread_address.tlv.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of value",
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_unknown,
      { "Unknown",
        "thread_address.tlv.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown TLV, raw value",
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_sub_tlvs,
      { "Sub-TLV(s)",
        "thread_address.tlv.sub_tlvs",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    /* Type-Specific TLV Fields */
    { &hf_thread_address_tlv_target_eid,
      { "Target EID",
        "thread_address.tlv.target_eid",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_ext_mac_addr,
      { "Extended MAC Address",
        "thread_address.tlv.ext_mac_addr",
        FT_EUI64, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_rloc16,
      { "RLOC16",
        "thread_address.tlv.rloc16",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_ml_eid,
      { "ML-EID",
        "thread_address.tlv.ml_eid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_address_tlv_status,
      { "Status",
        "thread_address.tlv.status",
        FT_UINT8, BASE_DEC, VALS(thread_address_tlv_status_vals), 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_attached_time,
      { "Attached Time",
        "thread_address.tlv.attached_time",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_last_transaction_time,
      { "Last Transaction Time",
        "thread_address.tlv.last_transaction_time",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_router_mask_id_seq,
      { "ID Sequence",
        "thread_address.tlv.router_mask_id_seq",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_address_tlv_router_mask_assigned,
      { "Assigned Router ID Mask",
        "thread_address.tlv.router_mask_assigned",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_nd_option,
      { "ND Option",
        "thread_address.tlv.nd_option",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_address_tlv_nd_data,
      { "ND Data",
        "thread_address.tlv.nd_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    }
  };
  
  static gint *ett[] = {
    &ett_thread_address,
    &ett_thread_address_tlv,
  };

  static ei_register_info ei[] = {
    { &ei_thread_address_tlv_length_failed, { "thread_address.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
    { &ei_thread_address_len_size_mismatch, { "thread_address.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
  };

  expert_module_t* expert_thread_address;

  proto_thread_address = proto_register_protocol("Thread Address", "Thread Address", "thread_address");
  proto_register_field_array(proto_thread_address, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_thread_address = expert_register_protocol(proto_thread_address);
  expert_register_field_array(expert_thread_address, ei, array_length(ei));

  register_dissector("thread_address", dissect_thread_address, proto_thread_address);
}

void
proto_reg_handoff_thread_address(void)
{
  static gboolean thread_address_initialized = FALSE;

  if (!thread_address_initialized) {
    thread_nwd_handle = find_dissector("thread_nwd");
    thread_address_initialized = TRUE;
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
