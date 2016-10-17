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
#include <math.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>
#include <epan/range.h>
#include <epan/oui.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/to_str.h>

/* Forward declarations */
void proto_register_thread_mc(void);
void proto_reg_handoff_thread_mc(void);

#define THREAD_MC_TLV_LENGTH_ESC  0xFF
#define THREAD_MC_32768_TO_NSEC_FACTOR ((double)30517.578125)
#define THREAD_MC_TSTAMP_MASK_U_MASK 0x80
#define THREAD_MC_SEC_POLICY_MASK_O_MASK 0x80
#define THREAD_MC_SEC_POLICY_MASK_N_MASK 0x40
#define THREAD_MC_SEC_POLICY_MASK_R_MASK 0x20
#define THREAD_MC_SEC_POLICY_MASK_C_MASK 0x10
#define THREAD_MC_SEC_POLICY_MASK_B_MASK 0x08
#define THREAD_MC_STACK_VER_REV_MASK 0x0F
#define THREAD_MC_STACK_VER_MIN_MASK 0xF0
#define THREAD_MC_STACK_VER_MAJ_MASK 0x0F
#define THREAD_MC_DISCOVERY_REQ_MASK_VER_MASK 0xF0
#define THREAD_MC_DISCOVERY_REQ_MASK_J_MASK 0x08
#define THREAD_MC_DISCOVERY_RSP_MASK_VER_MASK 0xF0
#define THREAD_MC_DISCOVERY_RSP_MASK_N_MASK 0x08
#define THREAD_MC_INVALID_CHAN_COUNT 0xFFFF

static int proto_thread_mc = -1;

static int hf_thread_mc_tlv = -1;
static int hf_thread_mc_tlv_type = -1;
static int hf_thread_mc_tlv_length8 = -1;
static int hf_thread_mc_tlv_length16 = -1;
static int hf_thread_mc_tlv_unknown = -1;
static int hf_thread_mc_tlv_sub_tlvs = -1;

/* Channel TLV fields */
static int hf_thread_mc_tlv_channel_page = -1;
static int hf_thread_mc_tlv_channel = -1;

/* PAN ID TLV fields */
static int hf_thread_mc_tlv_pan_id = -1;

/* Extended PAN ID TLV fields */
static int hf_thread_mc_tlv_xpan_id = -1;

/* Network Name TLV fields */
static int hf_thread_mc_tlv_net_name = -1;

/* PSKc TLV fields */
static int hf_thread_mc_tlv_pskc = -1;

/* Master Key TLV fields */
static int hf_thread_mc_tlv_master_key = -1;

/* Network Key Sequence TLV fields */
static int hf_thread_mc_tlv_net_key_seq_ctr = -1;

/* Mesh Local ULA TLV fields */
static int hf_thread_mc_tlv_ml_prefix = -1;

/* Steering Data TLV fields */
static int hf_thread_mc_tlv_steering_data = -1;

/* Border Agent Locator TLV fields */
static int hf_thread_mc_tlv_ba_locator = -1;

/* Commissioner ID TLV fields */
static int hf_thread_mc_tlv_commissioner_id = -1;

/* Commissioner ID TLV fields */
static int hf_thread_mc_tlv_commissioner_sess_id = -1;

/* Security Policy TLV fields */
static int hf_thread_mc_tlv_sec_policy_rot = -1;
static int hf_thread_mc_tlv_sec_policy_o = -1;
static int hf_thread_mc_tlv_sec_policy_n = -1;
static int hf_thread_mc_tlv_sec_policy_r = -1;
static int hf_thread_mc_tlv_sec_policy_c = -1;
static int hf_thread_mc_tlv_sec_policy_b = -1;

/* State TLV fields */
static int hf_thread_mc_tlv_state = -1;

/* Timestamp TLV fields */
static int hf_thread_mc_tlv_active_tstamp = -1;
static int hf_thread_mc_tlv_pending_tstamp = -1;

/* Delay Timer TLV fields */
static int hf_thread_mc_tlv_delay_timer = -1;

/* UDP Encapsulation TLV fields */
static int hf_thread_mc_tlv_udp_encap_src_port = -1;
static int hf_thread_mc_tlv_udp_encap_dst_port = -1;

/* IPv6 Address fields */
static int hf_thread_mc_tlv_ipv6_addr = -1;

/* UDP Port TLV fields */
static int hf_thread_mc_tlv_udp_port = -1;

/* IID TLV fields */
static int hf_thread_mc_tlv_iid = -1;

/* Joiner Router locator TLV fields */
static int hf_thread_mc_tlv_jr_locator = -1;

/* KEK TLV fields */
static int hf_thread_mc_tlv_kek = -1;

/* Provisioning URL TLV fields */
static int hf_thread_mc_tlv_provisioning_url = -1;

/* Vendor TLV fields */
static int hf_thread_mc_tlv_vendor_name = -1;
static int hf_thread_mc_tlv_vendor_model = -1;
static int hf_thread_mc_tlv_vendor_sw_ver = -1;
static int hf_thread_mc_tlv_vendor_data = -1;
static int hf_thread_mc_tlv_vendor_stack_ver_oui = -1;
static int hf_thread_mc_tlv_vendor_stack_ver_build = -1;
static int hf_thread_mc_tlv_vendor_stack_ver_rev = -1;
static int hf_thread_mc_tlv_vendor_stack_ver_min = -1;
static int hf_thread_mc_tlv_vendor_stack_ver_maj = -1;

/* Channel Mask TLV fields */
static int hf_thread_mc_tlv_chan_mask = -1;
static int hf_thread_mc_tlv_chan_mask_page = -1;
static int hf_thread_mc_tlv_chan_mask_len = -1;
static int hf_thread_mc_tlv_chan_mask_mask = -1;

/* Count TLV fields */
static int hf_thread_mc_tlv_count = -1;

/* Period TLV fields */
static int hf_thread_mc_tlv_period = -1;

/* Period TLV fields */
static int hf_thread_mc_tlv_scan_duration = -1;

/* Energy List TLV fields */
static int hf_thread_mc_tlv_energy_list = -1;
static int hf_thread_mc_tlv_el_count = -1;

/* Discovery Request TLV fields */
static int hf_thread_mc_tlv_discovery_req_ver = -1;
static int hf_thread_mc_tlv_discovery_req_j = -1;

/* Discovery Response TLV fields */
static int hf_thread_mc_tlv_discovery_rsp_ver = -1;
static int hf_thread_mc_tlv_discovery_rsp_n = -1;

static gint ett_thread_mc = -1;
static gint ett_thread_mc_tlv = -1;
static gint ett_thread_mc_chan_mask = -1;
static gint ett_thread_mc_el_count = -1;

static expert_field ei_thread_mc_tlv_length_failed = EI_INIT;
static expert_field ei_thread_mc_len_size_mismatch = EI_INIT;
static expert_field ei_thread_mc_len_too_long      = EI_INIT;

static dissector_handle_t thread_mc_handle;
static dissector_handle_t thread_dtls_handle;
static dissector_handle_t thread_udp_handle;

#define THREAD_MC_TLV_CHANNEL                      0 /* Modified for new features */
#define THREAD_MC_TLV_PANID                        1
#define THREAD_MC_TLV_XPANID                       2
#define THREAD_MC_TLV_NETWORK_NAME                 3
#define THREAD_MC_TLV_PSKC                         4
#define THREAD_MC_TLV_NETWORK_MASTER_KEY           5
#define THREAD_MC_TLV_NETWORK_KEY_SEQ_CTR          6
#define THREAD_MC_TLV_NETWORK_ML_PREFIX            7
#define THREAD_MC_TLV_STEERING_DATA                8
#define THREAD_MC_TLV_BORDER_AGENT_LOCATOR         9
#define THREAD_MC_TLV_COMMISSIONER_ID              10
#define THREAD_MC_TLV_COMMISSIONER_SESSION_ID      11
#define THREAD_MC_TLV_SECURITY_POLICY              12
#define THREAD_MC_TLV_GET                          13
#define THREAD_MC_TLV_ACTIVE_TSTAMP                14 /* Was "Commissioning Dataset Timestamp TLV" */
#define THREAD_MC_TLV_COMMISSIONER_UDP_PORT        15
#define THREAD_MC_TLV_STATE                        16
#define THREAD_MC_TLV_JOINER_DTLS_ENCAP            17
#define THREAD_MC_TLV_JOINER_UDP_PORT              18
#define THREAD_MC_TLV_JOINER_IID                   19
#define THREAD_MC_TLV_JOINER_ROUTER_LOCATOR        20
#define THREAD_MC_TLV_JOINER_KEK                   21
/* Gap */
#define THREAD_MC_TLV_PROVISIONING_URL             32
#define THREAD_MC_TLV_VENDOR_NAME                  33
#define THREAD_MC_TLV_VENDOR_MODEL                 34
#define THREAD_MC_TLV_VENDOR_SW_VERSION            35
#define THREAD_MC_TLV_VENDOR_DATA                  36
#define THREAD_MC_TLV_VENDOR_STACK_VERSION         37
/* Gap */
#define THREAD_MC_TLV_UDP_ENCAPSULATION            48
#define THREAD_MC_TLV_IPV6_ADDRESS                 49
/* Gap */
/* New features */
#define THREAD_MC_TLV_PENDING_TSTAMP               51
#define THREAD_MC_TLV_DELAY_TIMER                  52
#define THREAD_MC_TLV_CHANNEL_MASK                 53
#define THREAD_MC_TLV_COUNT                        54
#define THREAD_MC_TLV_PERIOD                       55
#define THREAD_MC_TLV_SCAN_DURATION                56
#define THREAD_MC_TLV_ENERGY_LIST                  57
/* Gap */
/* New discovery mechanism */
#define THREAD_MC_TLV_DISCOVERY_REQUEST            128
#define THREAD_MC_TLV_DISCOVERY_RESPONSE           129

static const value_string thread_mc_tlv_vals[] = {
{ THREAD_MC_TLV_CHANNEL,                   "Channel" },
{ THREAD_MC_TLV_PANID,                     "PAN ID" },
{ THREAD_MC_TLV_XPANID,                    "Extended PAN ID" },
{ THREAD_MC_TLV_NETWORK_NAME,              "Network Name" },
{ THREAD_MC_TLV_PSKC,                      "PSKc" },
{ THREAD_MC_TLV_NETWORK_MASTER_KEY,        "Network Master Key" },
{ THREAD_MC_TLV_NETWORK_KEY_SEQ_CTR,       "Network Key Sequence Counter" },
{ THREAD_MC_TLV_NETWORK_ML_PREFIX,         "Mesh Local ULA Prefix" },
{ THREAD_MC_TLV_STEERING_DATA,             "Steering Data" },
{ THREAD_MC_TLV_BORDER_AGENT_LOCATOR,      "Border Agent Locator" },
{ THREAD_MC_TLV_COMMISSIONER_ID,           "Commissioner ID" },
{ THREAD_MC_TLV_COMMISSIONER_SESSION_ID,   "Commissioner Session ID" },
{ THREAD_MC_TLV_SECURITY_POLICY,           "Security Policy" },
{ THREAD_MC_TLV_GET,                       "Get" },
{ THREAD_MC_TLV_ACTIVE_TSTAMP,             "Active Timestamp" },
{ THREAD_MC_TLV_COMMISSIONER_UDP_PORT,     "Commissioner UDP Port" },
{ THREAD_MC_TLV_STATE,                     "State" },
{ THREAD_MC_TLV_JOINER_DTLS_ENCAP,         "Joiner DTLS Encapsulation" },
{ THREAD_MC_TLV_JOINER_UDP_PORT,           "Joiner UDP Port" },
{ THREAD_MC_TLV_JOINER_IID,                "Joiner IID" },
{ THREAD_MC_TLV_JOINER_ROUTER_LOCATOR,     "Joiner Router Locator" },
{ THREAD_MC_TLV_JOINER_KEK,                "Joiner KEK" },
{ THREAD_MC_TLV_PROVISIONING_URL,          "Provisioning URL" },
{ THREAD_MC_TLV_VENDOR_NAME,               "Vendor Name" },
{ THREAD_MC_TLV_VENDOR_MODEL,              "Vendor Model" },
{ THREAD_MC_TLV_VENDOR_SW_VERSION,         "Vendor Software Version" },
{ THREAD_MC_TLV_VENDOR_DATA,               "Vendor Data" },
{ THREAD_MC_TLV_VENDOR_STACK_VERSION,      "Vendor Stack Version" },
{ THREAD_MC_TLV_UDP_ENCAPSULATION,         "UDP Encapsulation" },
{ THREAD_MC_TLV_IPV6_ADDRESS,              "IPv6 Address" },
/* New features */
{ THREAD_MC_TLV_PENDING_TSTAMP,            "Pending Timestamp" },
{ THREAD_MC_TLV_DELAY_TIMER,               "Delay Timer" },
{ THREAD_MC_TLV_CHANNEL_MASK,              "Channel Mask" },
{ THREAD_MC_TLV_COUNT,                     "Count" },
{ THREAD_MC_TLV_PERIOD,                    "Period" },
{ THREAD_MC_TLV_SCAN_DURATION,             "Scan Duration" },
{ THREAD_MC_TLV_ENERGY_LIST,               "Energy List" },
/* New discovery mechanism */
{ THREAD_MC_TLV_DISCOVERY_REQUEST,         "Discovery Request" },
{ THREAD_MC_TLV_DISCOVERY_RESPONSE,        "Discovery Response" }
};

/* TODO: These are not "states" */
static const value_string thread_mc_state_vals[] = {
{ -1, "Reject" },
{ 0, "Pending" },
{ 1, "Accept" }
};

typedef enum {
    MC_LENGTH8 = 0,
    MC_LENGTH16
} mc_length_e;

static const true_false_string thread_mc_tlv_allowed = {
    "Allowed",
    "Not Allowed"
};

static const true_false_string thread_mc_tlv_enabled = {
    "Enabled",
    "Disabled"
};

static const true_false_string thread_mc_tlv_join_intent = {
    "Intending",
    "Not Intending"
};

typedef struct {
    guint16 src_port;
    guint16 dst_port;
    guint16 length;
    guint16 checksum;
} udp_hdr_t;

static guint
count_bits_in_byte(guint8 byte)
{
    static const guint8 lut[16] = {0, /* 0b0000 */
                                   1, /* 0b0001 */
                                   1, /* 0b0010 */
                                   2, /* 0b0011 */
                                   1, /* 0b0100 */
                                   2, /* 0b0101 */
                                   2, /* 0b0110 */
                                   3, /* 0b0111 */
                                   1, /* 0b1000 */
                                   2, /* 0b1001 */
                                   2, /* 0b1010 */ 
                                   3, /* 0b1011 */ 
                                   2, /* 0b1100 */ 
                                   3, /* 0b1101 */ 
                                   3, /* 0b1110 */ 
                                   4  /* 0b1111 */};
    return lut[byte >> 4] + lut[byte & 0xf];
}

static guint
get_chancount(tvbuff_t *tvb)
{
    guint       offset;
    guint8      tlv_type;
    guint16     tlv_len;
    mc_length_e tlv_mc_len;
    guint       chancount = THREAD_MC_INVALID_CHAN_COUNT;
   
    offset = 0;
    
    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the type and length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_type = tvb_get_guint8(tvb, offset);
        tlv_len = (guint16)tvb_get_guint8(tvb, offset + 1);
        
        /* TODO: need to make sure this applies to all MeshCoP TLVs */
        if (THREAD_MC_TLV_LENGTH_ESC == tlv_len) {
            /* 16-bit length field */
            tlv_len = tvb_get_ntohs(tvb, offset + 2);
            tlv_mc_len = MC_LENGTH16;
        } else {
            tlv_mc_len = MC_LENGTH8;
        }
 
        /* Skip over Type */
        offset++;

        /* Skip over Length */
        switch (tlv_mc_len) {
            case MC_LENGTH8:
                offset++;
                break;
            case MC_LENGTH16:
                offset += 3; /* Including escape byte */
                break;
            default:
                break;
        }
                
        switch(tlv_type) {
                
            case THREAD_MC_TLV_CHANNEL_MASK:
                {
                    int i, j;
                    guint8 entries = 0;
                    guint16 check_len = tlv_len;
                    guint8 check_offset = offset + 1; /* Channel page first */
                    guint8 masklen;

                    /* Check consistency of entries */
                    while (check_len > 0) {

                        masklen = tvb_get_guint8(tvb, check_offset);
                        if (masklen == 0) {
                            break; /* Get out or we might spin forever */
                        }
                        masklen += 2; /* Add in page and length */
                        check_offset += masklen;
                        check_len -= masklen;
                        entries++;
                    }

                    if (check_len != 0) {
                        /* Not an integer number of entries */
                        offset += tlv_len;
                        return chancount;
                    } else {
                        chancount = 0;
                        for (i = 0; i < entries; i++) {
                            /* Skip over channel page */
                            offset++;
                            masklen = tvb_get_guint8(tvb, offset);
                            offset++;
                            /* Count the number of channels in the channel mask */
                            for (j = 0; j < masklen; j++) {
                                chancount += count_bits_in_byte(tvb_get_guint8(tvb, offset));
                                offset++;
                            }
                        }
                    }
                }
                break;
                
            default:
                /* Skip over any other TLVs */
                offset += tlv_len;           
        }        
    }
    return chancount;
}

static int
dissect_thread_mc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *volatile proto_root = NULL;
    proto_tree  *volatile thread_mc_tree = NULL;
    proto_tree  *tlv_tree;
    guint       offset;
    proto_item  *ti;
    proto_item  *pi;
    guint8      tlv_type;
    guint16     tlv_len;
    mc_length_e tlv_mc_len;
    guint       chancount;

   
    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_thread_mc, tvb, 0, tvb_reported_length(tvb), "Thread MeshCoP");
        thread_mc_tree = proto_item_add_subtree(proto_root, ett_thread_mc);
    }

    offset = 0;

    /* Get channel count a priori so we can process energy list better */
    chancount = get_chancount(tvb);
    
    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the type and length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_type = tvb_get_guint8(tvb, offset);
        tlv_len = (guint16)tvb_get_guint8(tvb, offset + 1);
        
        /* TODO: need to make sure this applies to all MeshCoP TLVs */
        if (THREAD_MC_TLV_LENGTH_ESC == tlv_len) {
            /* 16-bit length field */
            tlv_len = tvb_get_ntohs(tvb, offset + 2);
            tlv_mc_len = MC_LENGTH16;
        } else {
            tlv_mc_len = MC_LENGTH8;
        }
 
        /* Create the tree */
        ti = proto_tree_add_item(thread_mc_tree, hf_thread_mc_tlv, tvb, offset, tlv_len, FALSE);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_mc_tlv);
        
        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_type, tvb, offset, 1, FALSE);
        offset++;
    
        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s", val_to_str(tlv_type, thread_mc_tlv_vals, "Unknown (%d)"));

        /* Length */
        switch (tlv_mc_len) {
            case MC_LENGTH8:
                proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_length8, tvb, offset, 1, FALSE);
                offset++;
                break;
            case MC_LENGTH16:
                proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_length16, tvb, offset + 1, 2, FALSE);
                offset += 3; /* Including escape byte */
                break;
            default:
                break;
        }
                
        switch(tlv_type) {
            case THREAD_MC_TLV_CHANNEL:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 3) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Channel page */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_channel_page, tvb, offset, 1, FALSE);
                        /* Channel */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_channel, tvb, offset+1, 2, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MC_TLV_PANID:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* PAN ID */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_pan_id, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_XPANID:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* PAN ID */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_xpan_id, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_NETWORK_NAME:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len > 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        gchar *str;
                        
                        str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tlv_len, ENC_UTF_8);
                        proto_tree_add_string(tlv_tree, hf_thread_mc_tlv_net_name, tvb, offset, tlv_len, str);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_PSKC:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_pskc, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_NETWORK_MASTER_KEY:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_master_key, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_NETWORK_KEY_SEQ_CTR:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 4) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_net_key_seq_ctr, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;
    
            case THREAD_MC_TLV_NETWORK_ML_PREFIX:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        struct e_in6_addr prefix;

                        memset(&prefix, 0, sizeof(prefix));
                        tvb_memcpy(tvb, (guint8 *)&prefix.bytes, offset, tlv_len);
                        pi = proto_tree_add_ipv6(tlv_tree, hf_thread_mc_tlv_ml_prefix, tvb, offset, tlv_len, &prefix);
                        proto_item_append_text(pi, "/%d", tlv_len * 8);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_STEERING_DATA:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len > 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Display it simply */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_steering_data, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;

            case THREAD_MC_TLV_BORDER_AGENT_LOCATOR:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ba_locator, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_COMMISSIONER_ID:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len > 64) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        gchar *str;
                        
                        str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tlv_len, ENC_UTF_8);
                        proto_tree_add_string(tlv_tree, hf_thread_mc_tlv_commissioner_id, tvb, offset, tlv_len, str);
                    }
                    offset += tlv_len;           
                }
                break;

            case THREAD_MC_TLV_COMMISSIONER_SESSION_ID:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_commissioner_sess_id, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_SECURITY_POLICY:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 3) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                        offset += tlv_len;
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_rot, tvb, offset, 2, FALSE);
                        offset += 2;
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_o, tvb, offset, 1, FALSE);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_n, tvb, offset, 1, FALSE);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_r, tvb, offset, 1, FALSE);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_c, tvb, offset, 1, FALSE);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_b, tvb, offset, 1, FALSE);
                        offset++;
                    }
                }
                break;

            case THREAD_MC_TLV_GET:
                {
                    int i;
                    
                    proto_item_append_text(ti, ")");

                    for (i = 0; i < tlv_len; i++) {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_type, tvb, offset, 1, FALSE);
                        offset++;
                    }
                }
                break;

            case THREAD_MC_TLV_ACTIVE_TSTAMP:
            case THREAD_MC_TLV_PENDING_TSTAMP:
                {
                    nstime_t timestamp;
                    
                    proto_item_append_text(ti, ")");
                    
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Fill in the nstime_t structure */
                        timestamp.secs = (time_t)tvb_get_ntoh48(tvb, offset);
                        timestamp.nsecs = (int)lround((double)(tvb_get_ntohs(tvb, offset + 6) >> 1) * THREAD_MC_32768_TO_NSEC_FACTOR);
                        if (tlv_type == THREAD_MC_TLV_ACTIVE_TSTAMP) {
                            proto_tree_add_time(tlv_tree, hf_thread_mc_tlv_active_tstamp, tvb, offset, 8, &timestamp);
                        } else {
                            proto_tree_add_time(tlv_tree, hf_thread_mc_tlv_pending_tstamp, tvb, offset, 8, &timestamp);
                        }
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_STATE:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_state, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MC_TLV_JOINER_DTLS_ENCAP:
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
                
            case THREAD_MC_TLV_COMMISSIONER_UDP_PORT:
            case THREAD_MC_TLV_JOINER_UDP_PORT:
                {
                    proto_item_append_text(ti, ")");

                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* UDP Port */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_udp_port, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MC_TLV_JOINER_IID:
                {
                    proto_item_append_text(ti, ")");
                    
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* IID */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_iid, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MC_TLV_JOINER_ROUTER_LOCATOR:
                {
                    proto_item_append_text(ti, ")");
                    
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_jr_locator, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MC_TLV_JOINER_KEK:
                {
                    proto_item_append_text(ti, ")");
                    
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_kek, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MC_TLV_PROVISIONING_URL:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len > 64) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        gchar *str;
                        
                        str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tlv_len, ENC_UTF_8);
                        proto_tree_add_string(tlv_tree, hf_thread_mc_tlv_provisioning_url, tvb, offset, tlv_len, str);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_VENDOR_NAME:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len > 32) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        gchar *str;
                        
                        str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tlv_len, ENC_UTF_8);
                        proto_tree_add_string(tlv_tree, hf_thread_mc_tlv_vendor_name, tvb, offset, tlv_len, str);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_VENDOR_MODEL:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent: TODO not specified in spec. */
                    if (tlv_len > 32) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        gchar *str;
                        
                        str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tlv_len, ENC_UTF_8);
                        proto_tree_add_string(tlv_tree, hf_thread_mc_tlv_vendor_model, tvb, offset, tlv_len, str);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_VENDOR_SW_VERSION:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len > 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        gchar *str;
                        
                        str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tlv_len, ENC_UTF_8);
                        proto_tree_add_string(tlv_tree, hf_thread_mc_tlv_vendor_sw_ver, tvb, offset, tlv_len, str);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_VENDOR_DATA:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len > 64) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        /* Display it simply */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_data, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;
                
            case THREAD_MC_TLV_VENDOR_STACK_VERSION:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 6) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                        offset += tlv_len;           
                    } else {
                        guint8 build_u8;
                        guint16 build;

                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_oui, tvb, offset, 3, FALSE);
                        offset += 3;
                        build_u8 = tvb_get_guint8(tvb, offset);
                        offset++;
                        build = (guint16)build_u8 << 4;
                        build_u8 = tvb_get_guint8(tvb, offset);
                        build |= (guint16)build_u8 >> 4;
                        pi = proto_tree_add_uint(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_build, tvb, 0, 0, build);
                        PROTO_ITEM_SET_GENERATED(pi);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_rev, tvb, offset, 1, FALSE);
                        offset++;
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_min, tvb, offset, 1, FALSE);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_maj, tvb, offset, 1, FALSE);
                        offset++;
                    }
                }
                break;
                
            case THREAD_MC_TLV_UDP_ENCAPSULATION:
                {
                    tvbuff_t *sub_tvb;
                    guint16 src_port;
                    guint16 dst_port;
                    udp_hdr_t *udp_hdr;
                    guint8 *buffer;
                    
                    proto_item_append_text(ti, ")");
                    src_port = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_udp_encap_src_port, tvb, offset, 2, FALSE);
                    offset += 2;
                    dst_port = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_udp_encap_dst_port, tvb, offset, 2, FALSE);
                    offset += 2;
                    
                    /* Allocate a buffer for the fake UDP datagram and create the fake header. */
                    /* Use wmem_alloc() in preference */
                    // buffer = (guint8 *)g_malloc(tlv_len + 4); /* Include 4 extra bytes for length and checksum */
                    buffer = (guint8 *)wmem_alloc(wmem_packet_scope(), tlv_len + 4);
                    
                    /* Create pseudo UDP header */
                    udp_hdr = (udp_hdr_t *)buffer;
                    udp_hdr->src_port = g_htons(src_port);
                    udp_hdr->dst_port = g_htons(dst_port);
                    udp_hdr->length = g_htons(tlv_len + 4); /* Includes UDP header length */
                    udp_hdr->checksum = 0;
                    /* Copy UDP payload in */
                    tvb_memcpy(tvb, udp_hdr + 1, offset, tlv_len - 4);
                    /* Create child tvb */
                    sub_tvb = tvb_new_child_real_data(tvb, buffer, tlv_len + 4, tvb_reported_length(tvb) + 4);
                    //tvb_set_free_cb(sub_tvb, g_free);
                    call_dissector(thread_udp_handle, sub_tvb, pinfo, tlv_tree);
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MC_TLV_IPV6_ADDRESS:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ipv6_addr, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;

            /* case THREAD_MC_TLV_PENDING_TSTAMP: Handled in THREAD_MC_TLV_ACTIVE_TSTAMP case */

            case THREAD_MC_TLV_DELAY_TIMER:
                {
                    proto_item_append_text(ti, ")");
                    
                    if (tlv_len != 4) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_delay_timer, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MC_TLV_CHANNEL_MASK:
                {
                    proto_tree *cm_tree;
                    int i;
                    guint8 entries = 0;
                    guint16 check_len = tlv_len;
                    guint8 check_offset = offset + 1; /* Channel page first */
                    guint8 masklen;

                    /* Check consistency of entries */
                    while (check_len > 0) {

                        masklen = tvb_get_guint8(tvb, check_offset);
                        if (masklen == 0) {
                            break; /* Get out or we might spin forever */
                        }
                        masklen += 2; /* Add in page and length */
                        check_offset += masklen;
                        check_len -= masklen;
                        entries++;
                    }

                    proto_item_append_text(ti, ")");
                    if (check_len != 0) {
                        /* Not an integer number of entries */
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_tlv_length_failed);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                        offset += tlv_len;
                    } else {
                        for (i = 0; i < entries; i++) {
                            pi = proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_chan_mask, tvb, offset, 1, FALSE);
                            cm_tree = proto_item_add_subtree(pi, ett_thread_mc_chan_mask);
                            proto_tree_add_item(cm_tree, hf_thread_mc_tlv_chan_mask_page, tvb, offset, 1, FALSE);
                            offset++;
                            masklen = tvb_get_guint8(tvb, offset);
                            proto_tree_add_item(cm_tree, hf_thread_mc_tlv_chan_mask_len, tvb, offset, 1, FALSE);
                            offset++;
                            proto_tree_add_item(cm_tree, hf_thread_mc_tlv_chan_mask_mask, tvb, offset, masklen, FALSE);
                            offset += masklen;
                        }
                    }
                }
                break;
                
            case THREAD_MC_TLV_COUNT:
                {
                    proto_item_append_text(ti, ")");

                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_count, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_PERIOD:
                {
                    proto_item_append_text(ti, ")");

                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_period, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_SCAN_DURATION:
                {
                    proto_item_append_text(ti, ")");

                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_scan_duration, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_ENERGY_LIST:
                {
                    proto_tree *it_tree;
                    int i;
                    
                    proto_item_append_text(ti, ")");
                    if ((chancount != THREAD_MC_INVALID_CHAN_COUNT) && ((tlv_len % chancount) == 0)) {
                        /* Go through the number of el_counts of scan */
                        for (i = 0; i < (int)(tlv_len / (guint16)chancount); i++) {
                            pi = proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_el_count, tvb, offset, 1, FALSE);
                            proto_item_append_text(pi, " %d", i + 1);
                            it_tree = proto_item_add_subtree(pi, ett_thread_mc_el_count);
                            proto_tree_add_item(it_tree, hf_thread_mc_tlv_energy_list, tvb, offset, chancount, FALSE);
                            offset += chancount;
                        }
                    } else {
                        /* This might not work but try and display as string */
                        /* Something wrong with channel count so just show it as a simple string */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_energy_list, tvb, offset, tlv_len, FALSE);
                    }
                    offset += tlv_len;
                }
                break;
                
            case THREAD_MC_TLV_DISCOVERY_REQUEST:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_discovery_req_ver, tvb, offset, 1, FALSE);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_discovery_req_j, tvb, offset, 1, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;

            case THREAD_MC_TLV_DISCOVERY_RESPONSE:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_discovery_rsp_ver, tvb, offset, 1, FALSE);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_discovery_rsp_n, tvb, offset, 1, FALSE);
                    }
                    offset += tlv_len;           
                }
                break;
                
            default:                
                proto_item_append_text(ti, ")");
                proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, FALSE);
                offset += tlv_len;           
        }        
    }
    return tvb_captured_length(tvb);
}


void
proto_register_thread_mc(void)
{
  static hf_register_info hf[] = {

    /* Generic TLV */
    { &hf_thread_mc_tlv,
      { "TLV",
        "thread_meshcop.tlv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Type-Length-Value",
        HFILL
      }
    },

    { &hf_thread_mc_tlv_type,
      { "Type",
        "thread_meshcop.tlv.type",
        FT_UINT8, BASE_DEC, VALS(thread_mc_tlv_vals), 0x0,
        "Type of value",
        HFILL
      }
    },

    { &hf_thread_mc_tlv_length8,
      { "Length",
        "thread_meshcop.tlv.len8",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of value (8-bit)",
        HFILL
      }
    },

    { &hf_thread_mc_tlv_length16,
      { "Length",
        "thread_meshcop.tlv.len16",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of value (16-bit)",
        HFILL
      }
    },

    { &hf_thread_mc_tlv_unknown,
      { "Unknown",
        "thread_meshcop.tlv.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown TLV, raw value",
        HFILL
      }
    },

    { &hf_thread_mc_tlv_sub_tlvs,
      { "Sub-TLV(s)",
        "thread_meshcop.tlv.sub_tlvs",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    /* Type-Specific TLV Fields */
    { &hf_thread_mc_tlv_channel_page,
      { "Channel Page",
        "thread_meshcop.tlv.channel_page",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_channel,
      { "Channel",
        "thread_meshcop.tlv.channel",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_pan_id,
      { "PAN ID",
        "thread_meshcop.tlv.pan_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_xpan_id,
      { "Extended PAN ID",
        "thread_meshcop.tlv.xpan_id",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_net_name,
      { "Network Name",
        "thread_meshcop.tlv.net_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_pskc,
      { "PSKc",
        "thread_meshcop.tlv.pskc",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_master_key,
      { "Master Key",
        "thread_meshcop.tlv.master_key",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_net_key_seq_ctr,
      { "Network Key Sequence Counter",
        "thread_meshcop.tlv.net_key_seq_ctr",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_ml_prefix,
      { "Mesh Local Prefix",
        "thread_meshcop.tlv.ml_prefix",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_steering_data,
      { "Steering Data",
        "thread_meshcop.tlv.steering_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_ba_locator,
      { "Border Agent Locator",
        "thread_meshcop.tlv.ba_locator",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_commissioner_id,
      { "Commissioner ID",
        "thread_meshcop.tlv.commissioner_id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_commissioner_sess_id,
      { "Commissioner Session ID",
        "thread_meshcop.tlv.commissioner_sess_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_sec_policy_rot,
      { "Rotation Time",
        "thread_meshcop.tlv.sec_policy_rot",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_mc_tlv_sec_policy_o,
      { "Out-of-band Commissioning",
        "thread_meshcop.tlv.sec_policy_o",
        FT_BOOLEAN, 8, TFS(&thread_mc_tlv_allowed), THREAD_MC_SEC_POLICY_MASK_O_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_sec_policy_n,
      { "Native Commissioning",
        "thread_meshcop.tlv.sec_policy_n",
        FT_BOOLEAN, 8, TFS(&thread_mc_tlv_allowed), THREAD_MC_SEC_POLICY_MASK_N_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_sec_policy_r,
      { "Thread 1.x Routers",
        "thread_meshcop.tlv.sec_policy_r",
        FT_BOOLEAN, 8, TFS(&thread_mc_tlv_enabled), THREAD_MC_SEC_POLICY_MASK_R_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_sec_policy_c,
      { "PSKc-based Commissioning",
        "thread_meshcop.tlv.sec_policy_c",
        FT_BOOLEAN, 8, TFS(&thread_mc_tlv_allowed), THREAD_MC_SEC_POLICY_MASK_C_MASK,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_mc_tlv_sec_policy_b,
      { "Thread 1.x Beacons",
        "thread_meshcop.tlv.sec_policy_b",
        FT_BOOLEAN, 8, TFS(&thread_mc_tlv_enabled), THREAD_MC_SEC_POLICY_MASK_B_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_state,
      { "State",
        "thread_meshcop.tlv.state",
        FT_INT8, BASE_DEC, VALS(thread_mc_state_vals), 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_active_tstamp,
      { "Active Timestamp",
        "thread_meshcop.tlv.active_tstamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_pending_tstamp,
      { "Pending Timestamp",
        "thread_meshcop.tlv.pending_tstamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_udp_port,
      { "UDP Port",
        "thread_meshcop.tlv.udp_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_iid,
      { "Interface Identifier",
        "thread_meshcop.tlv.iid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_jr_locator,
      { "Joiner Router Locator",
        "thread_meshcop.tlv.jr_locator",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_kek,
      { "Key Encryption Key (KEK)",
        "thread_meshcop.tlv.kek",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_provisioning_url,
      { "Provisioning URL",
        "thread_meshcop.tlv.provisioning_url",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_vendor_name,
      { "Vendor Name",
        "thread_meshcop.tlv.vendor_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_vendor_model,
      { "Vendor Model",
        "thread_meshcop.tlv.vendor_model",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_vendor_sw_ver,
      { "Vendor Software Version",
        "thread_meshcop.tlv.vendor_sw_ver",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_vendor_data,
      { "Vendor Data",
        "thread_meshcop.tlv.vendor_model",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_vendor_stack_ver_oui,
      { "OUI",
        "thread_meshcop.tlv.vendor_stack_ver_oui",
        FT_UINT24, BASE_HEX, VALS(oui_vals), 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_vendor_stack_ver_build,
      { "Build",
        "thread_meshcop.tlv.vendor_stack_ver_build",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_vendor_stack_ver_rev,
      { "Revision",
        "thread_meshcop.tlv.vendor_stack_ver_rev",
        FT_UINT8, BASE_DEC, NULL, THREAD_MC_STACK_VER_REV_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_vendor_stack_ver_min,
      { "Minor",
        "thread_meshcop.tlv.vendor_stack_ver_min",
        FT_UINT8, BASE_DEC, NULL, THREAD_MC_STACK_VER_MIN_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_vendor_stack_ver_maj,
      { "Major",
        "thread_meshcop.tlv.vendor_stack_ver_maj",
        FT_UINT8, BASE_DEC, NULL, THREAD_MC_STACK_VER_MAJ_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_udp_encap_src_port,
      { "Source UDP Port",
        "thread_meshcop.tlv.udp_encap_src_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_udp_encap_dst_port,
      { "Destination UDP Port",
        "thread_meshcop.tlv.udp_encap_dst_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_ipv6_addr,
      { "IPv6 Address",
        "thread_meshcop.tlv.ipv6_addr",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_delay_timer,
      { "Delay Timer",
        "thread_meshcop.tlv.delay_timer",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_chan_mask,
      { "Channel Mask",
        "thread_meshcop.tlv.chan_mask",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_chan_mask_page,
      { "Channel Page",
        "thread_meshcop.tlv.chan_mask_page",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_mc_tlv_chan_mask_len,
      { "Mask Length",
        "thread_meshcop.tlv.chan_mask_len",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_chan_mask_mask,
      { "Mask",
        "thread_meshcop.tlv.chan_mask_mask",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_el_count,
      { "Count",
        "thread_meshcop.tlv.el_count",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_count,
      { "Count",
        "thread_meshcop.tlv.count",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_period,
      { "Period",
        "thread_meshcop.tlv.period",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_scan_duration,
      { "Scan Duration",
        "thread_meshcop.tlv.scan_duration",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL,
        HFILL
      }
    },

    { &hf_thread_mc_tlv_energy_list,
      { "Energy List",
        "thread_meshcop.tlv.energy_list",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_mc_tlv_discovery_req_ver,
      { "Version",
        "thread_meshcop.tlv.discovery_req_ver",
        FT_UINT8, BASE_DEC, NULL, THREAD_MC_DISCOVERY_REQ_MASK_VER_MASK,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_mc_tlv_discovery_req_j,
      { "Joiner Flag",
        "thread_meshcop.tlv.discovery_req_j",
        FT_BOOLEAN, 8, TFS(&thread_mc_tlv_join_intent), THREAD_MC_DISCOVERY_REQ_MASK_J_MASK,
        NULL,
        HFILL
      }
    },
   
    { &hf_thread_mc_tlv_discovery_rsp_ver,
      { "Version",
        "thread_meshcop.tlv.discovery_rsp_ver",
        FT_UINT8, BASE_DEC, NULL, THREAD_MC_DISCOVERY_RSP_MASK_VER_MASK,
        NULL,
        HFILL
      }
    },
    
    { &hf_thread_mc_tlv_discovery_rsp_n,
      { "Native Commissioning",
        "thread_meshcop.tlv.discovery_rsp_n",
        FT_BOOLEAN, 8, TFS(&thread_mc_tlv_allowed), THREAD_MC_DISCOVERY_RSP_MASK_N_MASK,
        NULL,
        HFILL
      }
    }
  };
  
  static gint *ett[] = {
    &ett_thread_mc,
    &ett_thread_mc_tlv,
    &ett_thread_mc_chan_mask,
    &ett_thread_mc_el_count
  };

  static ei_register_info ei[] = {
    { &ei_thread_mc_tlv_length_failed, { "thread_meshcop.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
    { &ei_thread_mc_len_size_mismatch, { "thread_meshcop.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
    { &ei_thread_mc_len_too_long, { "thread_meshcop.len_too_long", PI_UNDECODED, PI_WARN, "TLV Length too long", EXPFILL }}
  };

  expert_module_t* expert_thread_mc;

  proto_thread_mc = proto_register_protocol("Thread MeshCoP", "Thread MeshCoP", "thread_meshcop");
  proto_register_field_array(proto_thread_mc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_thread_mc = expert_register_protocol(proto_thread_mc);
  expert_register_field_array(expert_thread_mc, ei, array_length(ei));

  register_dissector("thread_meshcop", dissect_thread_mc, proto_thread_mc);
}

void
proto_reg_handoff_thread_mc(void)
{
  static gboolean thread_mc_initialized = FALSE;

  if (!thread_mc_initialized) {
    thread_mc_handle = find_dissector("thread_meshcop");
    thread_dtls_handle = find_dissector("dtls");
    thread_udp_handle = find_dissector("udp");
    thread_mc_initialized = TRUE;
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
