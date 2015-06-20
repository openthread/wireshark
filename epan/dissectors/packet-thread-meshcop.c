/* packet-thread-meshcop.c
 * Routines for Thread Network Data packet dissection
 *
 * Robert Cragie <robert.cragie@arm.com>
 *
 * $Id: packet-thread-meshcop.c $
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
void proto_register_thread_meshcop(void);
void proto_reg_handoff_thread_meshcop(void);

#define THREAD_MESHCOP_TLV_LENGTH_ESC  0xFF

static int proto_thread_meshcop = -1;

static int hf_thread_meshcop_tlv = -1;
static int hf_thread_meshcop_tlv_type = -1;
static int hf_thread_meshcop_tlv_length8 = -1;
static int hf_thread_meshcop_tlv_length16 = -1;
static int hf_thread_meshcop_tlv_unknown = -1;
static int hf_thread_meshcop_tlv_sub_tlvs = -1;

/* Channel TLV fields */
static int hf_thread_meshcop_tlv_channel = -1;

/* PAN ID TLV fields */
static int hf_thread_meshcop_tlv_pan_id = -1;

/* Extended PAN ID TLV fields */
static int hf_thread_meshcop_tlv_x_pan_id = -1;

/* State TLV fields */
static int hf_thread_meshcop_tlv_state = -1;

/* UDP Port fields */
static int hf_thread_meshcop_tlv_udp_port = -1;

/* IID fields */
static int hf_thread_meshcop_tlv_iid = -1;

/* Router locator fields */
static int hf_thread_meshcop_tlv_router_locator = -1;

static gint ett_thread_meshcop = -1;
static gint ett_thread_meshcop_tlv = -1;

static expert_field ei_thread_meshcop_tlv_length_failed = EI_INIT;
static expert_field ei_thread_meshcop_len_size_mismatch = EI_INIT;

static dissector_handle_t thread_meshcop_handle;
static dissector_handle_t thread_dtls_handle;

#define THREAD_MESHCOP_TLV_CHANNEL                      0
#define THREAD_MESHCOP_TLV_PANID                        1
#define THREAD_MESHCOP_TLV_XPANID                       2
#define THREAD_MESHCOP_TLV_NETWORK_NAME                 3
#define THREAD_MESHCOP_TLV_COMMISSIONING_CREDENTIAL     4
#define THREAD_MESHCOP_TLV_NETWORK_MASTER_KEY           5
#define THREAD_MESHCOP_TLV_NETWORK_KEY_SEQUENCE         6
#define THREAD_MESHCOP_TLV_NETWORK_ML_ULA               7
#define THREAD_MESHCOP_TLV_STEERING_DATA                8
#define THREAD_MESHCOP_TLV_BORDER_ROUTER_LOCATOR        9
#define THREAD_MESHCOP_TLV_COMMISSIONER_ID              10
#define THREAD_MESHCOP_TLV_COMMISSIONER_SESSION_ID      11
#define THREAD_MESHCOP_TLV_SECURITY_POLICY              12
#define THREAD_MESHCOP_TLV_GET                          13
#define THREAD_MESHCOP_TLV_COMMISSIONING_DATA_TSTAMP    14
/* Gap */
#define THREAD_MESHCOP_TLV_STATE                        16
#define THREAD_MESHCOP_TLV_JOINER_DTLS_ENCAP            17
#define THREAD_MESHCOP_TLV_JOINER_UDP_PORT              18
#define THREAD_MESHCOP_TLV_JOINER_IID                   19
#define THREAD_MESHCOP_TLV_JOINER_ROUTER_LOCATOR        20
#define THREAD_MESHCOP_TLV_JOINER_KEK                   21
/* Gap */
#define THREAD_MESHCOP_TLV_PROVISIONING_URL             32
#define THREAD_MESHCOP_TLV_VENDOR_NAME                  33
#define THREAD_MESHCOP_TLV_VENDOR_MODEL                 34
#define THREAD_MESHCOP_TLV_VENDOR_SW_VERSION            35
#define THREAD_MESHCOP_TLV_VENDOR_DATA                  36
#define THREAD_MESHCOP_TLV_VENDOR_STACK_VERSION         37
/* Gap */
#define THREAD_MESHCOP_TLV_UDP_ENCAPSULATION            48
#define THREAD_MESHCOP_TLV_IPV6_ADDRESS                 49

static const value_string thread_meshcop_tlv_vals[] = {
{ THREAD_MESHCOP_TLV_CHANNEL,                   "Channel" },
{ THREAD_MESHCOP_TLV_PANID,                     "PAN ID" },
{ THREAD_MESHCOP_TLV_XPANID,                    "Extended PAN ID" },
{ THREAD_MESHCOP_TLV_NETWORK_NAME,              "Network Name" },
{ THREAD_MESHCOP_TLV_COMMISSIONING_CREDENTIAL,  "Commissioning Credential" },
{ THREAD_MESHCOP_TLV_NETWORK_MASTER_KEY,        "Network Master Key" },
{ THREAD_MESHCOP_TLV_NETWORK_KEY_SEQUENCE,      "Network Master Sequence" },
{ THREAD_MESHCOP_TLV_NETWORK_ML_ULA,            "Mesh Link ULA" },
{ THREAD_MESHCOP_TLV_STEERING_DATA,             "Steering Data" },
{ THREAD_MESHCOP_TLV_BORDER_ROUTER_LOCATOR,     "Border Router Locator" },
{ THREAD_MESHCOP_TLV_COMMISSIONER_ID,           "Commissioner ID" },
{ THREAD_MESHCOP_TLV_COMMISSIONER_SESSION_ID,   "Commissioner Session ID" },
{ THREAD_MESHCOP_TLV_SECURITY_POLICY,           "Security Policy" },
{ THREAD_MESHCOP_TLV_GET,                       "Get" },
{ THREAD_MESHCOP_TLV_COMMISSIONING_DATA_TSTAMP, "Commissioning Data Timestamp" },
{ THREAD_MESHCOP_TLV_STATE,                     "State" },
{ THREAD_MESHCOP_TLV_JOINER_DTLS_ENCAP,         "Joiner DTLS Encapsulation" },
{ THREAD_MESHCOP_TLV_JOINER_UDP_PORT,           "Joiner UDP Port" },
{ THREAD_MESHCOP_TLV_JOINER_IID,                "Joiner IID" },
{ THREAD_MESHCOP_TLV_JOINER_ROUTER_LOCATOR,     "Joiner Router Locator" },
{ THREAD_MESHCOP_TLV_JOINER_KEK,                "Joiner KEK" },
{ THREAD_MESHCOP_TLV_PROVISIONING_URL,          "Provisioning URL" },
{ THREAD_MESHCOP_TLV_VENDOR_NAME,               "Vendor Name" },
{ THREAD_MESHCOP_TLV_VENDOR_MODEL,              "Vendor Model" },
{ THREAD_MESHCOP_TLV_VENDOR_SW_VERSION,         "Vendor Software Version" },
{ THREAD_MESHCOP_TLV_VENDOR_DATA,               "Vendor Data" },
{ THREAD_MESHCOP_TLV_VENDOR_STACK_VERSION,      "Vendor Stack Version" },
{ THREAD_MESHCOP_TLV_UDP_ENCAPSULATION,         "UDP Encapsulation" },
{ THREAD_MESHCOP_TLV_IPV6_ADDRESS,              "IPv6 Address" }
};

typedef enum {
    MC_LENGTH8 = 0,
    MC_LENGTH16_NOESC,
    MC_LENGTH16_ESC
} mc_length_e;

static void
dissect_thread_meshcop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *volatile proto_root = NULL;
    proto_tree  *volatile thread_meshcop_tree = NULL;
    proto_tree  *tlv_tree;
    guint       offset;
    proto_item  *ti;
    guint8      tlv_type;
    guint16     tlv_len;
    mc_length_e tlv_mc_len;
   
    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_thread_meshcop, tvb, 0, tvb_length(tvb), "Thread MeshCoP");
        thread_meshcop_tree = proto_item_add_subtree(proto_root, ett_thread_meshcop);
    }

    offset = 0;
    
    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the type and length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_type = tvb_get_guint8(tvb, offset);
        tlv_len = (guint16)tvb_get_guint8(tvb, offset + 1);
        
        /* TODO: need to make sure this applies to all MeshCoP TLVs */
        if (THREAD_MESHCOP_TLV_JOINER_DTLS_ENCAP == tlv_type) {
            /* 16-bit length field */
            tlv_len = tvb_get_ntohs(tvb, offset + 1);
            tlv_mc_len = MC_LENGTH16_NOESC;
        } else if (THREAD_MESHCOP_TLV_LENGTH_ESC == tlv_len) {
            /* 16-bit length field */
            tlv_len = tvb_get_ntohs(tvb, offset + 2);
            tlv_mc_len = MC_LENGTH16_ESC;
        } else {
            tlv_mc_len = MC_LENGTH8;
        }
 
        /* Create the tree */
        ti = proto_tree_add_item(thread_meshcop_tree, hf_thread_meshcop_tlv, tvb, offset, tlv_len, FALSE);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_meshcop_tlv);
        
        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_type, tvb, offset, 1, FALSE);
        offset++;
    
        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s", val_to_str(tlv_type, thread_meshcop_tlv_vals, "Unknown (%d)"));

        /* Length */
        switch (tlv_mc_len) {
            case MC_LENGTH8:
                proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_length8, tvb, offset, 1, FALSE);
                offset++;
                break;
            case MC_LENGTH16_NOESC:
                proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_length16, tvb, offset, 2, FALSE);
                offset += 2;
            break;
            case MC_LENGTH16_ESC:
                proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_length16, tvb, offset, 2, FALSE);
                offset += 3; /* Including escape byte */
                break;
            default:
                break;
        }
                
        switch(tlv_type) {
            case THREAD_MESHCOP_TLV_CHANNEL:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_meshcop_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Channel */
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_channel, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MESHCOP_TLV_PANID:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_meshcop_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* PAN ID */
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_pan_id, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MESHCOP_TLV_XPANID:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_meshcop_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* PAN ID */
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_x_pan_id, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MESHCOP_TLV_STATE:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_meshcop_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Channel */
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_state, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MESHCOP_TLV_JOINER_DTLS_ENCAP:
                {
                    tvbuff_t *sub_tvb;
                    
                    proto_item_append_text(ti, ")");
                    if (tlv_len > 0) {
                        sub_tvb = tvb_new_subset_length(tvb, offset, tlv_len);
                        call_dissector(thread_dtls_handle, sub_tvb, pinfo, tlv_tree);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MESHCOP_TLV_JOINER_UDP_PORT:
                {
                    proto_item_append_text(ti, ")");

                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_meshcop_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* UDP Port */
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_udp_port, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MESHCOP_TLV_JOINER_IID:
                {
                    proto_item_append_text(ti, ")");
                    
//                    if (tlv_len != 8) {
                    if (0) {
                        expert_add_info(pinfo, proto_root, &ei_thread_meshcop_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* IID */
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_iid, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MESHCOP_TLV_JOINER_ROUTER_LOCATOR:
                {
                    proto_item_append_text(ti, ")");
                    
//                    if (tlv_len != 8) {
                    if (0) {
                        expert_add_info(pinfo, proto_root, &ei_thread_meshcop_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Router locator */
                        proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_router_locator, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MESHCOP_TLV_NETWORK_NAME:
            case THREAD_MESHCOP_TLV_COMMISSIONING_CREDENTIAL:
            case THREAD_MESHCOP_TLV_NETWORK_MASTER_KEY:
            case THREAD_MESHCOP_TLV_NETWORK_KEY_SEQUENCE:
            case THREAD_MESHCOP_TLV_NETWORK_ML_ULA:
            case THREAD_MESHCOP_TLV_STEERING_DATA:
            case THREAD_MESHCOP_TLV_BORDER_ROUTER_LOCATOR:
            case THREAD_MESHCOP_TLV_COMMISSIONER_ID:
            case THREAD_MESHCOP_TLV_COMMISSIONER_SESSION_ID:
            case THREAD_MESHCOP_TLV_SECURITY_POLICY:
            case THREAD_MESHCOP_TLV_GET:
            case THREAD_MESHCOP_TLV_COMMISSIONING_DATA_TSTAMP:
            case THREAD_MESHCOP_TLV_JOINER_KEK:
            case THREAD_MESHCOP_TLV_PROVISIONING_URL:
            case THREAD_MESHCOP_TLV_VENDOR_NAME:
            case THREAD_MESHCOP_TLV_VENDOR_MODEL:
            case THREAD_MESHCOP_TLV_VENDOR_SW_VERSION:
            case THREAD_MESHCOP_TLV_VENDOR_DATA:
            case THREAD_MESHCOP_TLV_VENDOR_STACK_VERSION:
            case THREAD_MESHCOP_TLV_UDP_ENCAPSULATION:
            case THREAD_MESHCOP_TLV_IPV6_ADDRESS:
            default:                
                proto_item_append_text(ti, ")");
                proto_tree_add_item(tlv_tree, hf_thread_meshcop_tlv_unknown, tvb, offset, tlv_len, FALSE);
                offset += tlv_len;           
        }        
    }
}

void
proto_register_thread_meshcop(void)
{
  static hf_register_info hf[] = {
    
    /* Generic TLV */
    { &hf_thread_meshcop_tlv,
      { "TLV",
        "thread_meshcop.tlv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Type-Length-Value",
        HFILL
      }
    },
        
    { &hf_thread_meshcop_tlv_type,
      { "Type",
        "thread_meshcop.tlv.type",
        FT_UINT8, BASE_DEC, VALS(thread_meshcop_tlv_vals), 0x0,
        "Type of value",
        HFILL
      }
    },

    { &hf_thread_meshcop_tlv_length8,
      { "Length",
        "thread_meshcop.tlv.len8",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of value (8-bit)",
        HFILL
      }
    },
    
    { &hf_thread_meshcop_tlv_length16,
      { "Length",
        "thread_meshcop.tlv.len16",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of value (16-bit)",
        HFILL
      }
    },
    
    { &hf_thread_meshcop_tlv_unknown,
      { "Unknown",
        "thread_meshcop.tlv.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown TLV, raw value",
        HFILL
      }
    },
    
    { &hf_thread_meshcop_tlv_sub_tlvs,
      { "Sub-TLV(s)",
        "thread_meshcop.tlv.sub_tlvs",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    /* Type-Specific TLV Fields */
    { &hf_thread_meshcop_tlv_channel,
      { "Channel",
        "thread_meshcop.tlv.channel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_meshcop_tlv_pan_id,
      { "PAN ID",
        "thread_meshcop.tlv.pan_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL
      }
    },
     
    { &hf_thread_meshcop_tlv_x_pan_id,
      { "Extended PAN ID",
        "thread_meshcop.tlv.x_pan_id",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_meshcop_tlv_state,
      { "State",
        "thread_meshcop.tlv.state",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_meshcop_tlv_udp_port,
      { "UDP Port",
        "thread_meshcop.tlv.udp_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_meshcop_tlv_iid,
      { "Interface Identifier",
        "thread_meshcop.tlv.iid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_meshcop_tlv_router_locator,
      { "Router Locator",
        "thread_meshcop.tlv.router_locator",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    }
  };
  
  static gint *ett[] = {
    &ett_thread_meshcop,
    &ett_thread_meshcop_tlv
  };

  static ei_register_info ei[] = {
    { &ei_thread_meshcop_tlv_length_failed, { "thread_meshcop.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
    { &ei_thread_meshcop_len_size_mismatch, { "thread_meshcop.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }}
  };

  expert_module_t* expert_thread_meshcop;

  proto_thread_meshcop = proto_register_protocol("Thread MeshCoP", "Thread MeshCoP", "thread_meshcop");
  proto_register_field_array(proto_thread_meshcop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_thread_meshcop = expert_register_protocol(proto_thread_meshcop);
  expert_register_field_array(expert_thread_meshcop, ei, array_length(ei));

  register_dissector("thread_meshcop", dissect_thread_meshcop, proto_thread_meshcop);
}

void
proto_reg_handoff_thread_meshcop(void)
{
  static gboolean thread_meshcop_initialized = FALSE;

  if (!thread_meshcop_initialized) {
    thread_meshcop_handle = find_dissector("thread_meshcop");
    thread_dtls_handle = find_dissector("dtls");
    thread_meshcop_initialized = TRUE;
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
