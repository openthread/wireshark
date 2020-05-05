/* packet-btsvc_toble.c
 * Routines for ToBLE service data dissection
 * Copyright 2018, Rafal Kuznia <rafal.kuznia@nordicsemi.no>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wmem/wmem.h>
#include "packet-bluetooth.h"
#include "packet-btl2cap.h"

#define MASKBIT(sh) (1<<sh)

/* ToBLE Beacon mandatory field sizes */
#define TOBLE_CONNECTION_FLAGS_SIZE       sizeof(guint8)
#define TOBLE_DISCOVERY_FLAGS_SIZE        sizeof(guint8)

/* ToBLE Beacon optional field sizes */
#define TOBLE_HEADER_SIZE                 sizeof(guint8)
#define TOBLE_PSM_SIZE                    sizeof(guint8)
#define TOBLE_PANID_SIZE                  sizeof(guint16)
#define TOBLE_SRC16_SIZE                  sizeof(guint16)
#define TOBLE_SRC64_SIZE                  sizeof(guint64)
#define TOBLE_DST16_SIZE                  sizeof(guint16)
#define TOBLE_DST64_SIZE                  sizeof(guint64)

/* ToBLE Beacon and Scan Response bit field masks */
#define TOBLE_CONTROL_FIELD_VERSION_MASK        0xf0
#define TOBLE_CONTROL_FIELD_OPCODE_MASK         0x0f

/* ToBLE Beacon bit field masks */
#define TOBLE_CONNECTION_FLAGS_L2_MASK    MASKBIT(7)
#define TOBLE_CONNECTION_FLAGS_RSVD_MASK        0x78
#define TOBLE_CONNECTION_FLAGS_EXT_MASK   MASKBIT(2)
#define TOBLE_CONNECTION_FLAGS_TX_MASK    MASKBIT(1)
#define TOBLE_CONNECTION_FLAGS_C_MASK     MASKBIT(0)

#define TOBLE_DISCOVERY_FLAGS_RSVD_MASK         0xc0
#define TOBLE_DISCOVERY_FLAGS_D_MASK      MASKBIT(5)
#define TOBLE_DISCOVERY_FLAGS_B_MASK      MASKBIT(4)
#define TOBLE_DISCOVERY_FLAGS_J_MASK      MASKBIT(3)
#define TOBLE_DISCOVERY_FLAGS_A_MASK      MASKBIT(2)
#define TOBLE_DISCOVERY_FLAGS_R_MASK      MASKBIT(1)
#define TOBLE_DISCOVERY_FLAGS_U_MASK      MASKBIT(0)

// TODO: we should rather use the ToBLE Service Data Header in conjunction with the opcode
// Dissector will stop working if verson changes e.g. from 3 to 4.
#define TOBLE_BEACON_HEADER_VALUE              0x30
#define TOBLE_SCAN_RESPONSE_HEADER_VALUE       0x31

/* Underlying protocols */
static int proto_btle = -1;     /* for advertising and scanning data */

/* WPAN dissector handle */
static dissector_handle_t wpan_dissector_handle;

/* ToBLE Service Data Header */
static int toble_service_data_header = -1;

/* ToBLE Control Field */
static int hf_toble_beacon_control_field_header = -1;
static int hf_toble_beacon_control_field_header_version = -1;
static int hf_toble_beacon_control_field_header_opcode = -1;

/* ToBLE Connection Flags */
static int hf_toble_connection_flags = -1;
static int hf_toble_connection_flag_l2cap = -1;
static int hf_toble_connection_flag_reserved = -1;
static int hf_toble_connection_flag_has_extended_dst_address = -1;
static int hf_toble_connection_flag_tx_ready = -1;
static int hf_toble_connection_flag_connect_ready = -1;

/* ToBLE Discovery Flags */
static int hf_toble_discovery_flags = -1;
static int hf_toble_discovery_flag_reserved = -1;
static int hf_toble_discovery_flag_dtc_enabled = -1;
static int hf_toble_discovery_flag_border_agent_enabled = -1;
static int hf_toble_discovery_flag_joining_permitted = -1;
static int hf_toble_discovery_flag_active_router = -1;
static int hf_toble_discovery_flag_router_capable = -1;
static int hf_toble_discovery_flag_unconfigured = -1;

/* Optional Fields */
static int hf_toble_psm   = -1;
static int hf_toble_panid = -1;
static int hf_toble_src16 = -1;
static int hf_toble_src64 = -1;
static int hf_toble_dst16 = -1;
static int hf_toble_dst64 = -1;

static int hf_toble_scan_tlv_joiner_iid    = -1;
static int hf_toble_scan_tlv_network_name  = -1;
static int hf_toble_scan_tlv_steering_data = -1;

static int hf_toble_scan_tlv_type   = -1;
static int hf_toble_scan_tlv_length = -1;
static int hf_toble_scan_tlv_value  = -1;

/* Initialize the subtree pointers */
static gint ett_toble_beacon = -1;
static gint ett_toble_beacon_service_data_header = -1;
static gint ett_toble_scan_response_service_data_header = -1;

static gint ett_toble_connection_flags = -1;
static gint ett_toble_discovery_flags = -1;
static gint ett_toble_joiner_iid = -1;
static gint ett_toble_network_name = -1;
static gint ett_toble_steering_data = -1;

/* ToBLE Beacon Control Field fileds */
static const int *hfx_toble_header_bit_fields[] =
{
    &hf_toble_beacon_control_field_header_version,
    &hf_toble_beacon_control_field_header_opcode,
    NULL
};

/* ToBLE Beacon Connection flags */
static const int *hfx_toble_connection_flags_bit_fields[] =
{
    &hf_toble_connection_flag_l2cap,
    &hf_toble_connection_flag_reserved,
    &hf_toble_connection_flag_has_extended_dst_address,
    &hf_toble_connection_flag_tx_ready,
    &hf_toble_connection_flag_connect_ready,
    NULL
};

/* ToBLE Beacon Discovery flags */
static const int *hfx_toble_discovery_flags_bit_fields[] =
{
    &hf_toble_discovery_flag_reserved,
    &hf_toble_discovery_flag_dtc_enabled,
    &hf_toble_discovery_flag_border_agent_enabled,
    &hf_toble_discovery_flag_joining_permitted,
    &hf_toble_discovery_flag_active_router,
    &hf_toble_discovery_flag_router_capable,
    &hf_toble_discovery_flag_unconfigured,
    NULL
};

/* Opcode value description */
static const value_string toble_opcode[] =
{
    { 0x00, "Beacon" },
    { 0x01, "Scan Response"},
    { 0, NULL }
};

guint dissect_toble_tlv(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    proto_item *ti = NULL;
    proto_tree *tt = NULL;
    guint8      type;
    guint8      length;

    type = tvb_get_guint8(tvb, offset);

    switch (type)
    {
    case 0x03: /* Network name TLV */
        ti = proto_tree_add_item(tree, hf_toble_scan_tlv_network_name, tvb, 3, -1, ENC_LITTLE_ENDIAN);
        tt = proto_item_add_subtree(ti, ett_toble_network_name);
        break;

    case 0x13: /* Joiner IID TLV */
        ti = proto_tree_add_item(tree, hf_toble_scan_tlv_joiner_iid, tvb, 0, -1, ENC_LITTLE_ENDIAN);
        tt = proto_item_add_subtree(ti, ett_toble_joiner_iid);
        break;

    case 0x66: /* Steering data TLV */
        ti = proto_tree_add_item(tree, hf_toble_scan_tlv_steering_data, tvb, 0, -1, ENC_LITTLE_ENDIAN);
        tt = proto_item_add_subtree(ti, ett_toble_steering_data);
        break;

    default:
        return 0;
    }

    offset += 1;

    length = tvb_get_guint8(tvb, offset);
    offset += 1;

    proto_tree_add_uint(tt, hf_toble_scan_tlv_type, tvb, offset - 2, 1, type);
    proto_tree_add_uint(tt, hf_toble_scan_tlv_length, tvb, offset - 1, 1, length);
    proto_tree_add_item(tt, hf_toble_scan_tlv_value, tvb, offset, length, ENC_LITTLE_ENDIAN);

    return length + 2;
}

/* Name:
 *      dissect_ll_frame
 *
 *  Parameters:
 *      tvb     -   buffer to be dissected
 *      pinfo   -   packet info
 *      tree    -   protocol tree
 *      data    -   packet data
 *
 *  Return value:
 *      int     -   length of dissected data or 0 if error
 *
 *  Purpose:
 *      Dissection procedure for ToBLE beacon/scan response
 */
int dissect_ll_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Main item and tree */
    proto_item *ti; /* Temporary item variable */
    proto_tree *tt; /* Temporary tree variable */
    proto_tree *entry_tree;

    guint8      header;     /* ToBLE beacon header. Used to deretmine if this is a beacon or scan response */
    guint       offset = 0; /* Dissection offset. */

    bluetooth_eir_ad_service_data_t *bt_eir_ad_data = (bluetooth_eir_ad_service_data_t *)data;

    /* Create main item and tree */
    ti = proto_tree_add_item(tree, toble_service_data_header, tvb, 0, -1, ENC_LITTLE_ENDIAN);
    entry_tree = proto_item_add_subtree(ti, ett_toble_beacon);

    /* Get header value */
    header = tvb_get_guint8(tvb, offset);

    /* Dissector recognizes ToBLE beacon by checking the first byte.
     *  If it is equal to 0x30 (version = 3, opcode = 0 - beacon) */
    /* Check if this is a beacon header */
    if (header == TOBLE_BEACON_HEADER_VALUE)
    {
        /* This is likely a ToBLE discovery beacon */
        guint8 connection_flags;
        guint8 psm;

        col_append_str(pinfo->cinfo, COL_INFO, ", ToBLE Beacon");

        /* Display header information (version and opcode) */
        ti = proto_tree_add_item(entry_tree, hf_toble_beacon_control_field_header, tvb, offset, TOBLE_HEADER_SIZE, ENC_LITTLE_ENDIAN);
        tt = proto_item_add_subtree(ti, ett_toble_beacon_service_data_header);

        proto_tree_add_bitmask_list(tt, tvb, offset, TOBLE_HEADER_SIZE, hfx_toble_header_bit_fields, ENC_NA);
        offset += TOBLE_HEADER_SIZE;

        /* Get connection flags */
        connection_flags = tvb_get_guint8(tvb, offset);

        ti = proto_tree_add_item(entry_tree, hf_toble_connection_flags, tvb, offset, TOBLE_CONNECTION_FLAGS_SIZE, ENC_LITTLE_ENDIAN);
        tt = proto_item_add_subtree(ti, ett_toble_connection_flags);

        proto_tree_add_bitmask_list(tt, tvb, offset, TOBLE_CONNECTION_FLAGS_SIZE, hfx_toble_connection_flags_bit_fields, ENC_NA);
        offset += TOBLE_CONNECTION_FLAGS_SIZE; /* One octet offset */

        /* Get discovery flags */
        // discovery_flags = tvb_get_guint8(tvb, offset);

        ti = proto_tree_add_item(entry_tree, hf_toble_discovery_flags, tvb, offset, TOBLE_DISCOVERY_FLAGS_SIZE, ENC_LITTLE_ENDIAN);
        tt = proto_item_add_subtree(ti, ett_toble_discovery_flags);

        proto_tree_add_bitmask_list(tt, tvb, offset, TOBLE_DISCOVERY_FLAGS_SIZE, hfx_toble_discovery_flags_bit_fields, ENC_NA);
        offset += TOBLE_DISCOVERY_FLAGS_SIZE;

        if (connection_flags & TOBLE_CONNECTION_FLAGS_L2_MASK)
        {
            /* Display L2CAP PSM */
            psm = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(entry_tree, hf_toble_psm, tvb, offset, TOBLE_PSM_SIZE, ENC_LITTLE_ENDIAN);
            offset += TOBLE_PSM_SIZE;

            if (pinfo->fd->flags.visited == FALSE)
            {
                btl2cap_psm_set_uuid(bt_eir_ad_data->bt_eir_ad_data->interface_id, bt_eir_ad_data->bt_eir_ad_data->adapter_id, psm, bt_eir_ad_data->uuid);
            }
        }

        if (connection_flags & TOBLE_CONNECTION_FLAGS_C_MASK)
        {
            /* Display PanID */
            proto_tree_add_item(entry_tree, hf_toble_panid, tvb, offset, TOBLE_PANID_SIZE, ENC_LITTLE_ENDIAN);
            offset += TOBLE_PANID_SIZE;

            /* Display SRC16 address */
            proto_tree_add_item(entry_tree, hf_toble_src16, tvb, offset, TOBLE_SRC16_SIZE, ENC_LITTLE_ENDIAN);
            offset += TOBLE_SRC16_SIZE;

            /* Display SRC64 address */
            proto_tree_add_item(entry_tree, hf_toble_src64, tvb, offset, TOBLE_SRC64_SIZE, ENC_BIG_ENDIAN);
            offset += TOBLE_SRC64_SIZE;
        }

        if (connection_flags & TOBLE_CONNECTION_FLAGS_TX_MASK)
        {
            /* Display DST16 if TX=1 and EXT=0 */
            if(!(connection_flags & TOBLE_CONNECTION_FLAGS_EXT_MASK))
            {
                proto_tree_add_item(entry_tree, hf_toble_dst16, tvb, offset, TOBLE_DST16_SIZE, ENC_LITTLE_ENDIAN);
                offset += TOBLE_DST16_SIZE;
            }
            else /* Display DST64 if TX=1 and EXT=1 */
            {
                proto_tree_add_item(entry_tree, hf_toble_dst64, tvb, offset, TOBLE_DST64_SIZE, ENC_BIG_ENDIAN);
                offset += TOBLE_DST64_SIZE;
            }
        }
    }
    /* Dissector recognizes ToBLE beacon by checking the first byte.
     *  If it is equal to 0x31 (version = 3, opcode = 1 - scan response) */
    /* Check if this is a scan response header */
    else if (header == TOBLE_SCAN_RESPONSE_HEADER_VALUE)
    {
        guint length = -1;

        col_append_str(pinfo->cinfo, COL_INFO, ", ToBLE Scan Response");

        /* Display header information (version and opcode) */
        ti = proto_tree_add_item(entry_tree, hf_toble_beacon_control_field_header, tvb, offset, TOBLE_HEADER_SIZE, ENC_LITTLE_ENDIAN);
        tt = proto_item_add_subtree(ti, ett_toble_scan_response_service_data_header);

        proto_tree_add_bitmask_list(tt, tvb, offset, TOBLE_HEADER_SIZE, hfx_toble_header_bit_fields, ENC_NA);
        offset += TOBLE_HEADER_SIZE;

        while (tvb_reported_length_remaining(tvb, offset) != 0 && length != 0)
        {
            length = dissect_toble_tlv(tvb, entry_tree, offset);
            offset += length;
        }
    }
    else
    {
        // Should not be here! How to throw an error?
    }

    return tvb_captured_length(tvb);
}

/* Name:
 *      dissect_toble_service_data_header
 *
 *  Parameters:
 *      tvb     -   buffer to be dissected
 *      pinfo   -   packet info
 *      tree    -   protocol tree
 *      data    -   packet
 *
 *  Return value:
 *      int     -   length of dissected data or 0 if error
 *
 *  Purpose:
 *      Dissection procedure for ToBLE data, both advertisement and WPAN
 */
static int
dissect_toble_service_data_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int                prev_proto;
    wmem_list_frame_t *prev_layer;
    /* In this case we distinguish between AD service data/WPAN transfer by checking previous dissector
     * If previous dissector was "btcommon" then we can be certain that this is a beacon/scan response.
     * If previous dissector was "btl2cap" then this is most likely a WPAN transfer.
     * In both cases ToBLE dissector is called through a single UUID.
     * Service data dissector obtains LE_PSM value from ToBLE beacon and assigns ToBLE UUID to in in le_psm_uuid_tree
     * defined in packet-btl2cap.h. During credit based L2CAP transfer L2CAP dissector obtains PSM associated with
     * current connection and looks up associated UUIDs. In such case if valid beacon was previously captured WPAN dissector
     * should be correctly called without any need for manual configuration.
     */
     /* Obtain previous protocol that called this dissector */
    prev_layer = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
    if (prev_layer != NULL)
    {
        /* Found previous protocol. Get it's ID */
        prev_proto = GPOINTER_TO_INT(wmem_list_frame_data(prev_layer));

        /* Check if advertising/scan response or WPAN transfer */
        if (prev_proto == proto_btle)
        {
            /* Advertising/scan response */
            dissect_ll_frame(tvb, pinfo, tree, data);
        }
        else if (prev_proto == proto_btl2cap)
        {
            /* WPAN transfer */
            call_dissector_with_data(wpan_dissector_handle, tvb, pinfo, tree, data);
            col_append_str(pinfo->cinfo, COL_INFO, ", sent through L2CAP");
        }
    }

    return tvb_captured_length(tvb);
}

/* Name:
 *       proto_register_btsvc_toble
 *
 *  Parameters:
 *       None
 *
 *  Return value:
 *       None
 *
 *  Purpose:
 *       Register the protocol with Wireshark.
 */
void
proto_register_btsvc_toble(void)
{
    /* Setup list of header fields. */
    static hf_register_info hf[] =
    {
        /* ToBLE Beacon header fields */
        {
            &hf_toble_beacon_control_field_header,
            {
                "Header", "toble.header",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_beacon_control_field_header_version,
            {
                "Version", "toble.header.version",
                FT_UINT8, BASE_DEC,
                NULL, TOBLE_CONTROL_FIELD_VERSION_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_beacon_control_field_header_opcode,
            {
                "Opcode", "toble.header.opcode",
                FT_UINT8, BASE_HEX,
                VALS(toble_opcode), TOBLE_CONTROL_FIELD_OPCODE_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_connection_flags,
            {
                "Connection flags", "toble.connection",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_connection_flag_l2cap,
            {
                "L2CAP transport", "toble.connection.l2cap",
                FT_BOOLEAN, 8,
                NULL, TOBLE_CONNECTION_FLAGS_L2_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_connection_flag_reserved,
            {
                "Reserved", "roble.role.reserved",
                FT_BOOLEAN, 8,
                NULL, TOBLE_CONNECTION_FLAGS_RSVD_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_connection_flag_has_extended_dst_address,
            {
                "Has Extended Destination Address", "toble.connection.has_extended_dst_address",
                FT_BOOLEAN, 8,
                NULL, TOBLE_CONNECTION_FLAGS_EXT_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_connection_flag_tx_ready,
            {
                "Transmission Ready", "toble.connection.tx_ready",
                FT_BOOLEAN, 8,
                NULL, TOBLE_CONNECTION_FLAGS_TX_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_connection_flag_connect_ready,
            {
                "Connect ready", "toble.connection.connect_ready",
                FT_BOOLEAN, 8,
                NULL, TOBLE_CONNECTION_FLAGS_C_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_discovery_flags,
            {
                "Discovery flags", "toble.discovery",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_discovery_flag_reserved,
            {
                "Reserved", "toble.discovery.reserved",
                FT_BOOLEAN, 8,
                NULL, TOBLE_DISCOVERY_FLAGS_RSVD_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_discovery_flag_dtc_enabled,
            {
                "DTC enabled", "toble.discovery.dtc_enabled",
                FT_BOOLEAN, 8,
                NULL, TOBLE_DISCOVERY_FLAGS_D_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_discovery_flag_border_agent_enabled,
            {
                "Border Agent Enabled", "toble.discovery.border_agent_enabled",
                FT_BOOLEAN, 8,
                NULL, TOBLE_DISCOVERY_FLAGS_B_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_discovery_flag_joining_permitted,
            {
                "Joining Permitted", "toble.discovery.joininig_permitted",
                FT_BOOLEAN, 8,
                NULL, TOBLE_DISCOVERY_FLAGS_J_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_discovery_flag_active_router,
            {
                "Active Router", "toble.discovery.active_router",
                FT_BOOLEAN, 8,
                NULL, TOBLE_DISCOVERY_FLAGS_A_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_discovery_flag_router_capable,
            {
                "Router Capable", "toble.discovery.router_capable",
                FT_BOOLEAN, 8,
                NULL, TOBLE_DISCOVERY_FLAGS_R_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_discovery_flag_unconfigured,
            {
                "Unconfigured", "toble.discovery.unconfigured",
                FT_BOOLEAN, 8,
                NULL, TOBLE_DISCOVERY_FLAGS_U_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_psm,
            {
                "PSM", "toble.psm",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_panid,
            {
                "PAN ID", "toble.panid",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_src16,
            {
                "SRC16 (RLOC)", "toble.src16",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_src64,
            {
                "SRC64 (MAC64)", "toble.src64",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_dst16,
            {
                "DST16 (RLOC)", "toble.dst16",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_dst64,
            {
                "DST64 (MAC64)", "toble.dst64",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        /* ToBLE scan response header fields */
            {
            &hf_toble_scan_tlv_joiner_iid,
            {
                "Joiner IID", "toble.joiner_iid",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_scan_tlv_network_name,
            {
                "Network name", "toble.network_name",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_scan_tlv_steering_data,
            {
                "Steering Data", "toble.steering_data",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_scan_tlv_type,
            {
                "Type", "toble.tlv.type",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_scan_tlv_length,
            {
                "Length", "toble.tlv.length",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_scan_tlv_value,
            {
                "Value", "toble.tlv.value",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
    {
        &ett_toble_beacon,
        &ett_toble_beacon_service_data_header,
        &ett_toble_scan_response_service_data_header,
        &ett_toble_connection_flags,
        &ett_toble_discovery_flags,
        &ett_toble_joiner_iid,
        &ett_toble_network_name,
        &ett_toble_steering_data
    };

    /* Register the protocol name and description */
    toble_service_data_header = proto_register_protocol("ToBLE data", "ToBLE", "toble");
    /* Register protocol fields */
    proto_register_field_array(toble_service_data_header, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/* Name
 *       proto_reg_handoff_btsvc_toble
 *
 *  Parameters:
 *      None
 *
 *  Return value:
 *      None
 *
 *  Purpose:
 *      Register BTLE service data dissector handle and hook it to UUID
 */
void
proto_reg_handoff_btsvc_toble(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t toble_beacon_handle;

    if (!initialized) {
        /* Create dissector handle */
        toble_beacon_handle = create_dissector_handle(dissect_toble_service_data_header, toble_service_data_header);

        /* Attach to UUIDs. Case sensitive. */
        // TODO: 0xfffb officially belongs to ToBLE now, should not be reported as unknown.
        dissector_add_string("bluetooth.uuid", "fffb", toble_beacon_handle);
        /* Get WPAN dissector without frame check sum */
        wpan_dissector_handle = find_dissector("wpan_nofcs");

        proto_btle = proto_get_id_by_filter_name("btcommon");

        initialized = TRUE;
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
