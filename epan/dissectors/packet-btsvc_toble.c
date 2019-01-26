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

/* ToBLE field sizes */
#define TOBLE_HEADER_SIZE                 sizeof(guint8)
#define TOBLE_FLAGS_SIZE                  sizeof(guint8)
#define TOBLE_DISCOVERY_ID_SIZE           sizeof(guint64)
#define TOBLE_LE_PSM_SIZE                 sizeof(guint8)
#define TOBLE_JOINER_UDP_TLV_SIZE         sizeof(guint32)
#define TOBLE_COMMISSIONER_UDP_TLV_SIZE   sizeof(guint32)
#define TOBLE_NETWORK_NAME_TYPE_SIZE      sizeof(guint8)
#define TOBLE_NETWORK_NAME_LENGTH_SIZE    sizeof(guint8)
#define TOBLE_STEERING_DATA_TYPE_SIZE     sizeof(guint8)
#define TOBLE_STEERING_DATA_LENGTH_SIZE   sizeof(guint8)

/* ToBLE bit field masks */
#define TOBLE_HEADER_VERSION_MASK               0xf0
#define TOBLE_HEADER_OPCODE_MASK                0x0f
#define TOBLE_FLAG_BORDER_AGENT_MASK            MASKBIT(7)
#define TOBLE_FLAG_DIRECT_COMMISSIONING_MASK    MASKBIT(6)
#define TOBLE_FLAG_UNCONFIGURED_MASK            MASKBIT(5)
#define TOBLE_FLAG_JOINING_PERMITTED_MASK       MASKBIT(4)
#define TOBLE_FLAG_ACTIVE_ROUTER_MASK           MASKBIT(3)
#define TOBLE_FLAG_ROUTER_CAPABLE_MASK          MASKBIT(2)
#define TOBLE_FLAG_RESERVED_MASK                MASKBIT(1)
#define TOBLE_FLAG_L2CAP_TRANSPORT_MASK         MASKBIT(0)

#define TOBLE_BEACON_HEADER_VALUE 0x30

/* Underlying protocols */
static int proto_btle = -1;     /* for advertising and scanning data */

/* WPAN dissector handle */
static dissector_handle_t wpan_dissector_handle;

/* ToBLE beacon header fields */
static int service_toble = -1;
static int hf_toble_header = -1;
static int hf_toble_header_version = -1;
static int hf_toble_header_opcode = -1;
static int hf_toble_flags = -1;
static int hf_toble_flag_border_agent = -1;
static int hf_toble_flag_direct_commissioning = -1;
static int hf_toble_flag_unconfigured = -1;
static int hf_toble_flag_joining_permitted = -1;
static int hf_toble_flag_router = -1;
static int hf_toble_flag_scanning_capable = -1;
static int hf_toble_flag_reserved = -1;
static int hf_toble_flag_l2cap_transport = -1;
static int hf_toble_joiner_iid = -1;
static int hf_toble_extended_panid = -1;
static int hf_toble_le_psm = -1;
static int hf_toble_joiner_udp_tlv = -1;
static int hf_toble_commissioner_udp_tlv = -1;

/* ToBLE scan resonse header fields */
static int hf_toble_network_name_type = -1;
static int hf_toble_network_name_length = -1;
static int hf_toble_network_name_value = -1;
static int hf_toble_steering_data_type = -1;
static int hf_toble_steering_data_length = -1;
static int hf_toble_steering_data_value = -1;

/* Initialize the subtree pointers */
static gint ett_toble_beacon = -1;
static gint ett_toble_scan_response = -1;
static gint ett_toble_header = -1;
static gint ett_toble_flags = -1;

/* ToBLE beacon header bit fileds */
static const int *hfx_toble_header_bit_fields[] =
{
    &hf_toble_header_version,
    &hf_toble_header_opcode,
    NULL
};

/* ToBLE beacon flags */
static const int *hfx_toble_flags_bit_fields[] =
{
    &hf_toble_flag_border_agent,
    &hf_toble_flag_direct_commissioning,
    &hf_toble_flag_unconfigured,
    &hf_toble_flag_joining_permitted,
    &hf_toble_flag_router,
    &hf_toble_flag_scanning_capable,
    &hf_toble_flag_reserved,
    &hf_toble_flag_l2cap_transport,
    NULL
};

/* Opcode value description */
static const value_string toble_beacon_opcode[] =
{
    { 0x00, "Discovery" },
    { 0, NULL }
};

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
    proto_item *ti;
    proto_tree *header_tree;
    proto_tree *flags_tree;
    proto_tree *entry_tree;

    guint8      header;     /* ToBLE beacon header. Used to deretmine if this is a beacon or scan response */
    guint       offset = 0; /* Dissection offset. */

    bluetooth_eir_ad_service_data_t *bt_eir_ad_data = data;

    /* Create main item and tree */
    ti = proto_tree_add_item(tree, service_toble, tvb, 0, -1, ENC_LITTLE_ENDIAN);
    entry_tree = proto_item_add_subtree(ti, ett_toble_beacon);

    /* Get header value */
    header = tvb_get_guint8(tvb, offset);

    /* Dissector recognizes ToBLE beacon by checking the first byte.
     *  If it is equal to 0x30 (version = 3, opcode = 0 - discovery) */
    /* Check if this is a beacon header */
    if (header == TOBLE_BEACON_HEADER_VALUE)
    {
        /* This is likely a ToBLE discovery beacon */
        guint8 flags;
        guint8 le_psm;

        col_append_str(pinfo->cinfo, COL_INFO, ", ToBLE beacon");

        /* Display header information (version and opcode) */
        ti = proto_tree_add_item(entry_tree, hf_toble_header, tvb, offset, TOBLE_HEADER_SIZE, ENC_LITTLE_ENDIAN);
        header_tree = proto_item_add_subtree(ti, ett_toble_header);

        proto_tree_add_bitmask_list(header_tree, tvb, offset, TOBLE_HEADER_SIZE, hfx_toble_header_bit_fields, ENC_NA);
        offset += TOBLE_HEADER_SIZE;

        /* Get flags */
        flags = tvb_get_guint8(tvb, offset);
        /* Display beacon flags */
        ti = proto_tree_add_item(entry_tree, hf_toble_flags, tvb, offset, TOBLE_FLAGS_SIZE, ENC_LITTLE_ENDIAN);
        flags_tree = proto_item_add_subtree(ti, ett_toble_flags);

        proto_tree_add_bitmask_list(flags_tree, tvb, offset, TOBLE_FLAGS_SIZE, hfx_toble_flags_bit_fields, ENC_NA);
        offset += TOBLE_FLAGS_SIZE; /* Two octet offset */

        if (flags & TOBLE_FLAG_UNCONFIGURED_MASK)
        {
            /* Discovery ID field displayed as extended PANID */
            proto_tree_add_item(entry_tree, hf_toble_extended_panid, tvb, offset, TOBLE_DISCOVERY_ID_SIZE, ENC_LITTLE_ENDIAN);
        }
        else
        {
            /* Discovery ID field displayed as Joiner IID */
            proto_tree_add_item(entry_tree, hf_toble_joiner_iid, tvb, offset, TOBLE_DISCOVERY_ID_SIZE, ENC_LITTLE_ENDIAN);
        }
        offset += TOBLE_DISCOVERY_ID_SIZE;

        if (flags & TOBLE_FLAG_L2CAP_TRANSPORT_MASK)
        {
            /* Display ToBLE L2CAP PSM */
            le_psm = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(entry_tree, hf_toble_le_psm, tvb, offset, TOBLE_LE_PSM_SIZE, ENC_LITTLE_ENDIAN);
            offset += TOBLE_LE_PSM_SIZE;

            if (pinfo->fd->flags.visited == FALSE)
            {
                btl2cap_psm_set_uuid(bt_eir_ad_data->bt_eir_ad_data->interface_id, bt_eir_ad_data->bt_eir_ad_data->adapter_id, le_psm, bt_eir_ad_data->uuid);
            }
        }

        if (flags & TOBLE_FLAG_UNCONFIGURED_MASK)
        {
            /* Display Joiner UDP TLV */
            proto_tree_add_item(entry_tree, hf_toble_joiner_udp_tlv, tvb, offset, TOBLE_JOINER_UDP_TLV_SIZE, ENC_LITTLE_ENDIAN);
            offset += TOBLE_JOINER_UDP_TLV_SIZE;
        }

        if (flags & TOBLE_FLAG_BORDER_AGENT_MASK)
        {
            /* Display Commissioner UDP TLV */
            proto_tree_add_item(entry_tree, hf_toble_commissioner_udp_tlv, tvb, offset, TOBLE_COMMISSIONER_UDP_TLV_SIZE, ENC_LITTLE_ENDIAN);
            offset += TOBLE_COMMISSIONER_UDP_TLV_SIZE;
        }

    }
    else
    {
        guint8 length;
        /* This is a scan response */
        col_append_str(pinfo->cinfo, COL_INFO, ", ToBLE scan response");

        /* Display network name TLV */
        /* Type */
        proto_tree_add_item(entry_tree, hf_toble_network_name_type, tvb, offset, TOBLE_NETWORK_NAME_TYPE_SIZE, ENC_LITTLE_ENDIAN);
        offset += TOBLE_NETWORK_NAME_TYPE_SIZE;

        /* Length */
        length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(entry_tree, hf_toble_network_name_length, tvb, offset, TOBLE_NETWORK_NAME_LENGTH_SIZE, ENC_LITTLE_ENDIAN);
        offset += TOBLE_NETWORK_NAME_LENGTH_SIZE;

        /* Value */
        proto_tree_add_item(entry_tree, hf_toble_network_name_value, tvb, offset, length, ENC_LITTLE_ENDIAN);
        offset += length;

        /* Display steering data TLV */
        /* Type */
        proto_tree_add_item(entry_tree, hf_toble_steering_data_type, tvb, offset, TOBLE_STEERING_DATA_TYPE_SIZE, ENC_LITTLE_ENDIAN);
        offset += TOBLE_STEERING_DATA_TYPE_SIZE;

        /* Length */
        length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(entry_tree, hf_toble_steering_data_length, tvb, offset, TOBLE_STEERING_DATA_LENGTH_SIZE, ENC_LITTLE_ENDIAN);
        offset += TOBLE_STEERING_DATA_LENGTH_SIZE;

        /* Value */
        proto_tree_add_item(entry_tree, hf_toble_steering_data_value, tvb, offset, length, ENC_LITTLE_ENDIAN);
        offset += length;
    }

    return tvb_captured_length(tvb);
}

/* Name:
 *      dissect_service_toble
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
dissect_service_toble(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
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
        /* ToBLE discovery beacon header fields */
        {
            &hf_toble_header,
            {
                "Header", "toble.header",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_header_version,
            {
                "Version", "toble.header.version",
                FT_UINT8, BASE_DEC,
                NULL, TOBLE_HEADER_VERSION_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_header_opcode,
            {
                "Opcode", "toble.header.opcode",
                FT_UINT8, BASE_HEX,
                VALS(toble_beacon_opcode), TOBLE_HEADER_OPCODE_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_flags,
            {
                "Flags", "toble.flags",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_flag_border_agent,
            {
                "Border agent", "toble.flags.border_agent",
                FT_BOOLEAN, 8,
                NULL, TOBLE_FLAG_BORDER_AGENT_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_flag_direct_commissioning,
            {
                "Direct commissioning", "toble.flags.direct_commissioning",
                FT_BOOLEAN, 8,
                NULL, TOBLE_FLAG_DIRECT_COMMISSIONING_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_flag_unconfigured,
            {
                "Unconfigured", "toble.flags.unconfigured",
                FT_BOOLEAN, 8,
                NULL, TOBLE_FLAG_UNCONFIGURED_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_flag_joining_permitted,
            {
                "Joining permitted", "toble.flags.joining_permitted",
                FT_BOOLEAN, 8,
                NULL, TOBLE_FLAG_JOINING_PERMITTED_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_flag_router,
            {
                "Active router", "toble.flags.active_router",
                FT_BOOLEAN, 8,
                NULL, TOBLE_FLAG_ACTIVE_ROUTER_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_flag_scanning_capable,
            {
                "Router capable", "toble.flags.router_capable",
                FT_BOOLEAN, 8,
                NULL, TOBLE_FLAG_ROUTER_CAPABLE_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_flag_reserved,
            {
                "Reserved", "toble.flags.reserved",
                FT_BOOLEAN, 8,
                NULL, TOBLE_FLAG_RESERVED_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_flag_l2cap_transport,
            {
                "L2CAP transport", "toble.flags.l2cap_transport",
                FT_BOOLEAN, 8,
                NULL, TOBLE_FLAG_L2CAP_TRANSPORT_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_toble_joiner_iid,
            {
                "Joiner IID", "toble.joiner_iid",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_extended_panid,
            {
                "Extended PAN Identifier(XPANID)", "toble.xpanid",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_le_psm,
            {
                "LE PSM", "toble.le_psm",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_joiner_udp_tlv,
            {
                "Joiner UDP TLV", "toble.joiner_udp_tlv",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_commissioner_udp_tlv,
            {
                "Commissioner UDP TLV", "toble.commissioner_udp_tlv",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        /* ToBLE scan response header fields */
        {
            &hf_toble_network_name_type,
            {
                "Network Name type", "toble.network_name.type",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_network_name_length,
            {
                "Network Name length", "toble.network_name.length",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_network_name_value,
            {
                "Network Name value", "toble.network_name.value",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_steering_data_type,
            {
                "Steering Data type", "toble.steering_data.type",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_steering_data_length,
            {
                "Steering Data length", "toble.steering_data.length",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_toble_steering_data_value,
            {
                "Steering Data value", "toble.steering_data.value",
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
        &ett_toble_scan_response,
        &ett_toble_header,
        &ett_toble_flags
    };

    /* Register the protocol name and description */
    service_toble = proto_register_protocol("ToBLE data", "ToBLE", "toble");
    /* Register protocol fields */
    proto_register_field_array(service_toble, hf, array_length(hf));
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
        toble_beacon_handle = create_dissector_handle(dissect_service_toble, service_toble);

        /* Attach to UUIDs. Case sensitive. */
        dissector_add_string("bluetooth.uuid", "feaf", toble_beacon_handle);
        dissector_add_string("bluetooth.uuid", "8183", toble_beacon_handle);
        dissector_add_string("bluetooth.uuid", "0a03", toble_beacon_handle);
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
