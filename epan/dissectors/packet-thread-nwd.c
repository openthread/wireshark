/* packet-thread-nwd.c
 * Routines for Thread Network Data packet dissection
 *
 * Robert Cragie <robert.cragie@arm.com>
 *
 * $Id: packet-thread-nwd.c $
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
void proto_register_thread_nwd(void);
void proto_reg_handoff_thread_nwd(void);

static int proto_thread_nwd = -1;

static int hf_thread_nwd_tlv = -1;
static int hf_thread_nwd_tlv_type = -1;
static int hf_thread_nwd_tlv_stable = -1;
static int hf_thread_nwd_tlv_length = -1;
static int hf_thread_nwd_tlv_unknown = -1;
static int hf_thread_nwd_tlv_sub_tlvs = -1;

/* Has Route TLV fields */
static int hf_thread_nwd_tlv_has_route = -1;
static int hf_thread_nwd_tlv_has_route_br_16 = -1;
static int hf_thread_nwd_tlv_has_route_pref = -1;

/* Prefix TLV fields */
static int hf_thread_nwd_tlv_prefix = -1;
static int hf_thread_nwd_tlv_prefix_domain_id = -1;
static int hf_thread_nwd_tlv_prefix_length = -1;

/* Border Router TLV fields */
static int hf_thread_nwd_tlv_border_router = -1;
static int hf_thread_nwd_tlv_border_router_16 = -1;
static int hf_thread_nwd_tlv_border_router_pref = -1;
static int hf_thread_nwd_tlv_border_router_p = -1;
static int hf_thread_nwd_tlv_border_router_s = -1;
static int hf_thread_nwd_tlv_border_router_d = -1;
static int hf_thread_nwd_tlv_border_router_c = -1;
static int hf_thread_nwd_tlv_border_router_r = -1;
static int hf_thread_nwd_tlv_border_router_o = -1;
static int hf_thread_nwd_tlv_border_router_n = -1;

/* 6LoWPAN ID TLV fields */
static int hf_thread_nwd_tlv_6lowpan_id_6co_context_length = -1;
static int hf_thread_nwd_tlv_6lowpan_id_6co_flag = -1;
static int hf_thread_nwd_tlv_6lowpan_id_6co_flag_c = -1;
static int hf_thread_nwd_tlv_6lowpan_id_6co_flag_cid = -1;
static int hf_thread_nwd_tlv_6lowpan_id_6co_flag_reserved = -1;

/* Commissioning Data fields */
static int hf_thread_nwd_tlv_comm_data = -1;

/* Service fields */
static int hf_thread_nwd_tlv_service_t = -1;
static int hf_thread_nwd_tlv_service_s_id = -1;
static int hf_thread_nwd_tlv_service_s_ent_num = -1;
static int hf_thread_nwd_tlv_service_s_data_len = -1;
static int hf_thread_nwd_tlv_service_s_data = -1;

/* Server fields */
static int hf_thread_nwd_tlv_server_16 = -1;
static int hf_thread_nwd_tlv_server_data = -1;

static gint ett_thread_nwd = -1;
static gint ett_thread_nwd_tlv = -1;
static gint ett_thread_nwd_has_route = -1;
static gint ett_thread_nwd_6co_flag = -1;
static gint ett_thread_nwd_border_router = -1;
static gint ett_thread_nwd_prefix_sub_tlvs = -1;

static expert_field ei_thread_nwd_tlv_length_failed = EI_INIT;
static expert_field ei_thread_nwd_len_size_mismatch = EI_INIT;

static dissector_handle_t thread_nwd_handle;
static dissector_handle_t thread_mc_handle;

#define THREAD_NWD_TLV_HAS_ROUTE                    0
#define THREAD_NWD_TLV_PREFIX                       1
#define THREAD_NWD_TLV_BORDER_ROUTER                2
#define THREAD_NWD_TLV_6LOWPAN_ID                   3
#define THREAD_NWD_TLV_COMMISSIONING_DATA           4
#define THREAD_NWD_TLV_SERVICE                      5
#define THREAD_NWD_TLV_SERVER                       6

static const value_string thread_nwd_tlv_vals[] = {
{ THREAD_NWD_TLV_HAS_ROUTE,                 "Has Route" },
{ THREAD_NWD_TLV_PREFIX,                    "Prefix" },
{ THREAD_NWD_TLV_BORDER_ROUTER,             "Border Router" },
{ THREAD_NWD_TLV_6LOWPAN_ID,                "6LoWPAN ID" },
{ THREAD_NWD_TLV_COMMISSIONING_DATA,        "Commissioning Data" },
{ THREAD_NWD_TLV_SERVICE,                   "Service" },
{ THREAD_NWD_TLV_SERVER,                    "Server" }
};

#define THREAD_NWD_TLV_TYPE_M       0xFE
#define THREAD_NWD_TLV_STABLE_M     0x01

static const true_false_string tfs_thread_nwd_tlv_border_router_p = {
    "Autoconfigured preferred",
    "Autoconfigured deprecated"
};

static const true_false_string tfs_thread_nwd_tlv_border_router_s = {
    "SLAAC allowed",
    "SLAAC not allowed"
};

static const true_false_string tfs_thread_nwd_tlv_border_router_d = {
    "DHCPv6 allowed",
    "DHCPv6 not allowed"
};

static const true_false_string tfs_thread_nwd_tlv_border_router_c = {
    "Additional config. data",
    "No additional config. data"
};

static const true_false_string tfs_thread_nwd_tlv_border_router_r = {
    "Default route",
    "No default route"
};

static const true_false_string tfs_thread_nwd_tlv_border_router_o = {
    "On mesh",
    "Not on mesh"
};

static const true_false_string tfs_thread_nwd_tlv_border_router_n = {
    "DNS available",
    "DNS not available"
};

#define THREAD_NWD_TLV_HAS_ROUTE_ENTRY_SIZE 3
#define THREAD_NWD_TLV_HAS_ROUTE_PREF       0xC0

#define THREAD_NWD_TLV_BORDER_ROUTER_PREF   0xC0
#define THREAD_NWD_TLV_BORDER_ROUTER_P      0x20
#define THREAD_NWD_TLV_BORDER_ROUTER_S      0x10
#define THREAD_NWD_TLV_BORDER_ROUTER_D      0x08
#define THREAD_NWD_TLV_BORDER_ROUTER_C      0x04
#define THREAD_NWD_TLV_BORDER_ROUTER_R      0x02
#define THREAD_NWD_TLV_BORDER_ROUTER_O      0x01
#define THREAD_NWD_TLV_BORDER_ROUTER_N      0x80

#define ND_OPT_6CO_FLAG_C        0x10
#define ND_OPT_6CO_FLAG_CID      0x0F
#define ND_OPT_6CO_FLAG_RESERVED 0xE0

#define THREAD_NWD_TLV_SERVICE_T    0x80
#define THREAD_NWD_TLV_SERVICE_S_ID 0x0F

static int
dissect_thread_nwd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *volatile proto_root = NULL;
    proto_tree  *volatile thread_nwd_tree = NULL;
    proto_tree  *volatile flag_tree = NULL;
    proto_tree  *tlv_tree;
    tvbuff_t    *sub_tvb;
    guint       offset, tlv_offset;
    proto_item  *ti;
    guint8      tlv_type, tlv_len;
   
    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_thread_nwd, tvb, 0, tvb_reported_length(tvb), "Thread Network Data");
        thread_nwd_tree = proto_item_add_subtree(proto_root, ett_thread_nwd);
    }

    offset = 0;    
    
    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {
 
        /* Get the length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_len = tvb_get_guint8(tvb, offset + 1);
 
        ti = proto_tree_add_item(thread_nwd_tree, hf_thread_nwd_tlv, tvb, offset, tlv_len, FALSE);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_nwd_tlv);
        
        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_type, tvb, offset, 1, FALSE);
        tlv_type = tvb_get_guint8(tvb, offset) >> 1;

        /* Stable */
        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_stable, tvb, offset, 1, FALSE);
        offset++;
    
        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s", val_to_str(tlv_type, thread_nwd_tlv_vals, "Unknown (%d)"));

        /* Length */
        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_length, tvb, offset, 1, FALSE);
        offset++;
        
        switch(tlv_type) {
            case THREAD_NWD_TLV_HAS_ROUTE:
                {
                    /* Has Route TLV can be top level TLV or sub-TLV */
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if ((tlv_len % THREAD_NWD_TLV_HAS_ROUTE_ENTRY_SIZE) != 0)
                    {
                        expert_add_info(pinfo, proto_root, &ei_thread_nwd_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_unknown, tvb, offset, tlv_len, FALSE);
                        offset += tlv_len;
                    } else {
                        proto_tree *has_route_tree;
                        guint i;
                        guint count = tlv_len / THREAD_NWD_TLV_HAS_ROUTE_ENTRY_SIZE;

                        /* Add subtrees */
                        for (i = 0; i < count; i++) {
                            ti = proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_has_route, tvb, offset, 1, FALSE);
                            has_route_tree = proto_item_add_subtree(ti, ett_thread_nwd_has_route);
                            proto_tree_add_item(has_route_tree, hf_thread_nwd_tlv_has_route_br_16, tvb, offset, 2, FALSE);
                            offset += 2;
                            proto_tree_add_item(has_route_tree, hf_thread_nwd_tlv_has_route_pref, tvb, offset, 1, FALSE);
#if THREAD_NWD_TLV_HAS_ROUTE_ENTRY_SIZE == 3
                            offset++; /* Skip over remaining reserved bits */
#elif THREAD_NWD_TLV_HAS_ROUTE_ENTRY_SIZE == 4
                            offset += 2; /* Skip over remaining reserved bits */
#else
#error "THREAD_NWD_TLV_HAS_ROUTE_ENTRY_SIZE must be 3 or 4"
#endif
                        }
                    }
                }
                break;

            case THREAD_NWD_TLV_PREFIX:
                {
                    guint8 prefix_len;
                    guint8 prefix_byte_len;
                    struct e_in6_addr prefix;
                    address prefix_addr;

                    /* Domain ID */
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_prefix_domain_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    tlv_offset = 1;

                    /* Prefix Length */
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                    prefix_len = tvb_get_guint8(tvb, offset);
                    prefix_byte_len = (prefix_len + 7) / 8;
                    offset++;
                    tlv_offset++;

                    /* Prefix */
                    memset(&prefix.bytes, 0, sizeof(prefix));
                    tvb_memcpy(tvb, (guint8 *)&prefix.bytes, offset, prefix_byte_len);
                    proto_tree_add_ipv6(tlv_tree, hf_thread_nwd_tlv_prefix, tvb, offset, prefix_byte_len, &prefix);
                    set_address(&prefix_addr, AT_IPv6, 16, prefix.bytes);
                    proto_item_append_text(ti, " = %s/%d)", address_to_str(wmem_packet_scope(), &prefix_addr), prefix_len);
                    offset += prefix_byte_len;
                    tlv_offset += prefix_byte_len;
                    
                    if (tlv_offset < tlv_len) {
                        proto_tree *sub_tlv_tree;
                        guint remainder = tlv_len - tlv_offset;

                        ti = proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_sub_tlvs, tvb, offset, 1, FALSE);
                        sub_tlv_tree = proto_item_add_subtree(ti, ett_thread_nwd_prefix_sub_tlvs);
                        /* Call this dissector for sub-TLVs */
                        sub_tvb = tvb_new_subset_length(tvb, offset, remainder); /* remove prefix length (1) and prefix (prefix_byte_len) */
                        dissect_thread_nwd(sub_tvb, pinfo, sub_tlv_tree, data);
                        offset += remainder;
                    }
                }
                break;
            
            case THREAD_NWD_TLV_BORDER_ROUTER:
                {
                    /* Border Router TLV can only be sub-TLV */
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if ((tlv_len % 4) != 0)
                    {
                        expert_add_info(pinfo, proto_root, &ei_thread_nwd_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_unknown, tvb, offset, tlv_len, FALSE);
                        offset += tlv_len;
                    } else {
                        proto_tree *border_router_tree;
                        guint i;
                        guint count = tlv_len / 4;

                        /* Add subtrees */
                        for (i = 0; i < count; i++) {
                            ti = proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_border_router, tvb, offset, 1, FALSE);
                            border_router_tree = proto_item_add_subtree(ti, ett_thread_nwd_border_router);

                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_16, tvb, offset, 2, FALSE);
                            offset += 2;
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_pref, tvb, offset, 1, FALSE);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_p, tvb, offset, 1, FALSE);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_s, tvb, offset, 1, FALSE);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_d, tvb, offset, 1, FALSE);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_c, tvb, offset, 1, FALSE);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_r, tvb, offset, 1, FALSE);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_o, tvb, offset, 1, FALSE);
                            offset++;
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_n, tvb, offset, 1, FALSE);
                            offset++;
                        }
                    }
                }
                break;

            case THREAD_NWD_TLV_6LOWPAN_ID:
                {
                    /* 6lowpan-ND */
                    proto_item_append_text(ti, ")");
                    /*  Flags & CID */
                    ti = proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_6lowpan_id_6co_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                    flag_tree = proto_item_add_subtree(ti, ett_thread_nwd_6co_flag);
                    proto_tree_add_item(flag_tree, hf_thread_nwd_tlv_6lowpan_id_6co_flag_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flag_tree, hf_thread_nwd_tlv_6lowpan_id_6co_flag_c, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flag_tree, hf_thread_nwd_tlv_6lowpan_id_6co_flag_cid, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;

                    /* Context Length */
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_6lowpan_id_6co_context_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                break;

            case THREAD_NWD_TLV_COMMISSIONING_DATA:
                {
                    proto_item_append_text(ti, ")");
                    if (tlv_len > 0) {
                        sub_tvb = tvb_new_subset_length(tvb, offset, tlv_len);
                        call_dissector(thread_mc_handle, sub_tvb, pinfo, tlv_tree);
                    }
                    offset += tlv_len;
                }
                break;
            
            case THREAD_NWD_TLV_SERVICE:
                {
                    guint8 flags;
                    guint8 s_data_len;
                    
                    proto_item_append_text(ti, ")");

                    /* Flags and S_id */
                    flags = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_t, tvb, offset, 1, FALSE);
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_id, tvb, offset, 1, FALSE);
                    offset++;
                    tlv_offset = 1;

                    /* Enterprise number */
                    if ((flags & THREAD_NWD_TLV_SERVICE_T) == 0) {
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_ent_num, tvb, offset, 4, FALSE);
                        offset += 4;
                        tlv_offset += 4;
                    }

                    /* S_data */
                    s_data_len = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data_len, tvb, offset, 1, FALSE);
                    offset++;
                    tlv_offset++;
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data, tvb, offset, s_data_len, FALSE);
                    offset += s_data_len;
                    tlv_offset += s_data_len;

                    /* Server sub-TLVs */
                    if (tlv_offset < tlv_len) {
                        proto_tree *sub_tlv_tree;
                        guint remainder = tlv_len - tlv_offset;

                        ti = proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_sub_tlvs, tvb, offset, 1, FALSE);
                        sub_tlv_tree = proto_item_add_subtree(ti, ett_thread_nwd_prefix_sub_tlvs);
                        /* Call this dissector for sub-TLVs. Should only be server TLVs */
                        sub_tvb = tvb_new_subset_length(tvb, offset, remainder); /* remove prefix length (1) and prefix (prefix_byte_len) */
                        dissect_thread_nwd(sub_tvb, pinfo, sub_tlv_tree, data);
                        offset += remainder;
                    }
                }
                break;
            
            case THREAD_NWD_TLV_SERVER:
                {
                    proto_item_append_text(ti, ")");
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_server_16, tvb, offset, 2, FALSE);
                    offset += 2;
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_server_data, tvb, offset, tlv_len - 2, FALSE);
                    offset += tlv_len - 2;
                }
                break;

            default:                
                proto_item_append_text(ti, ")");
                proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_unknown, tvb, offset, tlv_len, FALSE);
                offset += tlv_len;
        }        
    }
    return tvb_captured_length(tvb);
}

void
proto_register_thread_nwd(void)
{
  static hf_register_info hf[] = {
    
    /* Generic TLV */
    { &hf_thread_nwd_tlv,
      { "TLV",
        "thread_nwd.tlv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Type-Length-Value",
        HFILL
      }
    },
        
    { &hf_thread_nwd_tlv_type,
      { "Type",
        "thread_nwd.tlv.type",
        FT_UINT8, BASE_DEC, VALS(thread_nwd_tlv_vals), THREAD_NWD_TLV_TYPE_M,
        "Type of value",
        HFILL
      }
    },

    { &hf_thread_nwd_tlv_stable,
      { "Stable",
        "thread_nwd.tlv.stable",
        FT_BOOLEAN, 8, NULL, THREAD_NWD_TLV_STABLE_M,
        "Stability or transience of network data",
        HFILL
      }
    },

    { &hf_thread_nwd_tlv_length,
      { "Length",
        "thread_nwd.tlv.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of value",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_unknown,
      { "Unknown",
        "thread_nwd.tlv.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown TLV, raw value",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_sub_tlvs,
      { "Sub-TLV(s)",
        "thread_nwd.tlv.sub_tlvs",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    /* Type-Specific TLV Fields */
    { &hf_thread_nwd_tlv_has_route,
      { "Has Route",
        "thread_nwd.tlv.has_route",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_has_route_br_16,
      { "Border Router 16",
        "thread_nwd.tlv.has_route.br_16",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Has Route Border Router 16-bit address",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_has_route_pref,
      { "Preference",
        "thread_nwd.tlv.has_route.pref",
        FT_UINT8, BASE_DEC, NULL, THREAD_NWD_TLV_HAS_ROUTE_PREF,
        "Has Route preference",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_prefix_domain_id,
      { "Domain ID",
        "thread_nwd.tlv.prefix.domain_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Prefix Domain ID",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_prefix_length,
      { "Prefix Length",
        "thread_nwd.tlv.prefix.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Prefix length",
        HFILL
      }
    },

    { &hf_thread_nwd_tlv_prefix,
      { "Prefix",
        "thread_nwd.tlv.prefix",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "Prefix",
        HFILL
      }
    },
        
    { &hf_thread_nwd_tlv_border_router,
      { "Border Router",
        "thread_nwd.tlv.border_router",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_border_router_16,
      { "Border Router 16",
        "thread_nwd.tlv.border_router.16",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Border Router 16-bit address",
        HFILL
      }
    },    
    
    { &hf_thread_nwd_tlv_border_router_pref,
      { "Preference",
        "thread_nwd.tlv.border_router.pref",
        FT_UINT8, BASE_DEC, NULL, THREAD_NWD_TLV_BORDER_ROUTER_PREF,
        "Value of P_preference",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_border_router_p,
      { "P Flag",
        "thread_nwd.tlv.border_router.flag.p",
        FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_p), THREAD_NWD_TLV_BORDER_ROUTER_P,
        "Value of P_preferred",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_border_router_s,
      { "S Flag",
        "thread_nwd.tlv.border_router.flag.s",
        FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_s), THREAD_NWD_TLV_BORDER_ROUTER_S,
        "Value of P_slaac",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_border_router_d,
      { "D Flag",
        "thread_nwd.tlv.border_router.flag.d",
        FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_d), THREAD_NWD_TLV_BORDER_ROUTER_D,
        "Value of P_dhcp",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_border_router_c,
      { "C Flag",
        "thread_nwd.tlv.border_router.flag.c",
        FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_c), THREAD_NWD_TLV_BORDER_ROUTER_C,
        "Value of P_configure",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_border_router_r,
      { "R Flag",
        "thread_nwd.tlv.border_router.flag.r",
        FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_r), THREAD_NWD_TLV_BORDER_ROUTER_R,
        "Value of P_default",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_border_router_o,
      { "O Flag",
        "thread_nwd.tlv.border_router.flag.o",
        FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_o), THREAD_NWD_TLV_BORDER_ROUTER_O,
        "Value of P_on_mesh",
        HFILL
      }
    },

    { &hf_thread_nwd_tlv_border_router_n,
      { "N Flag",
        "thread_nwd.tlv.border_router.flag.n",
        FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_n), THREAD_NWD_TLV_BORDER_ROUTER_N,
        "Value of P_nd_dns",
        HFILL
      }
    },

    { &hf_thread_nwd_tlv_6lowpan_id_6co_flag,
      { "Flag",
        "thread_nwd.tlv.6co.flag",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_6lowpan_id_6co_flag_c,
      { "Compression Flag",
        "thread_nwd.tlv.6co.flag.c",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), ND_OPT_6CO_FLAG_C,
        "This flag indicates if the context is valid for use in compression",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_6lowpan_id_6co_flag_cid,
      { "CID",
        "thread_nwd.tlv.6co.flag.cid",
        FT_UINT8, BASE_DEC, NULL, ND_OPT_6CO_FLAG_CID,
        "Context Identifier for this prefix information",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_6lowpan_id_6co_flag_reserved,
      { "Reserved",
        "thread_nwd.tlv.6co.flag.reserved",
        FT_UINT8, BASE_DEC, NULL, ND_OPT_6CO_FLAG_RESERVED,
        "Must be zero",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_6lowpan_id_6co_context_length,
      { "Context Length",
        "thread_nwd.tlv.6co.context_length",
        FT_UINT8, BASE_DEC, NULL, 0x00,
        "The number of leading bits in the Context Prefix field that are valid",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_comm_data,
      { "Commissioning Data",
        "thread_nwd.tlv.comm_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Commissioning data",
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_service_t,
      { "T flag",
        "thread_nwd.tlv.service.t",
        FT_UINT8, BASE_HEX, NULL, THREAD_NWD_TLV_SERVICE_T,
        NULL,
        HFILL
      }
    },

    { &hf_thread_nwd_tlv_service_s_id,
      { "Service Type ID",
        "thread_nwd.tlv.service.s_id",
        FT_UINT8, BASE_HEX, NULL, THREAD_NWD_TLV_SERVICE_S_ID,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_service_s_ent_num,
      { "Enterprise Number",
        "thread_nwd.tlv.service.s_ent_num",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_service_s_data_len,
      { "Service Data Length",
        "thread_nwd.tlv.service.s_data_len",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_nwd_tlv_service_s_data,
      { "Service Data",
        "thread_nwd.tlv.service.s_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Service data in raw bytes",
        HFILL
      }
    },

    { &hf_thread_nwd_tlv_server_16,
      { "Server 16",
        "thread_nwd.tlv.server.16",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Server 16-bit address",
        HFILL
      }
    },    
    
    { &hf_thread_nwd_tlv_server_data,
      { "Server Data",
        "thread_nwd.tlv.server.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Server data in raw bytes",
        HFILL
      }
    }
  };
  
  static gint *ett[] = {
    &ett_thread_nwd,
    &ett_thread_nwd_tlv,
    &ett_thread_nwd_has_route,
    &ett_thread_nwd_6co_flag,
    &ett_thread_nwd_border_router,
    &ett_thread_nwd_prefix_sub_tlvs
  };

  static ei_register_info ei[] = {
    { &ei_thread_nwd_tlv_length_failed, { "thread_nwd.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
    { &ei_thread_nwd_len_size_mismatch, { "thread_nwd.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
  };

  expert_module_t* expert_thread_nwd;

  proto_thread_nwd = proto_register_protocol("Thread Network Data", "Thread NWD", "thread_nwd");
  proto_register_field_array(proto_thread_nwd, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_thread_nwd = expert_register_protocol(proto_thread_nwd);
  expert_register_field_array(expert_thread_nwd, ei, array_length(ei));

  register_dissector("thread_nwd", dissect_thread_nwd, proto_thread_nwd);
}

void
proto_reg_handoff_thread_nwd(void)
{
  static gboolean thread_nwd_initialized = FALSE;

  if (!thread_nwd_initialized) {
    thread_nwd_handle = find_dissector("thread_nwd");
    thread_mc_handle = find_dissector("thread_meshcop");
    thread_nwd_initialized = TRUE;
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
