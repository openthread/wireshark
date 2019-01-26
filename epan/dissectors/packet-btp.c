/* packet-btp.c
 * Routines for BTP dissection
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
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>

#include "packet-bluetooth.h"
#include "packet-btatt.h"

/* Name:
 *       btp_handshake_t
 *  Purpose:
 *       Handshake request/response tracking
 */
typedef struct
{
    guint32      req_frame_id;   /* Request frame ID */
    guint32      rsp_frame_id;   /* Response frame ID */
    nstime_t     rsp_time;       /* Response time */
} btp_handshake_t;

/* Name:
 *       btp_transmission_t
 *  Purpose:
 *       Purpose: ACK tracking and reassembly
 */
typedef struct
{
    /* BTP data fields for ACK tracking */
    guint8       btp_sequence_number;
    guint8       btp_ack_number;
    /* Non-protocol data identifiers for reassembly */
    guint32      data_segment_id;
    guint32      data_message_id;
    /* ACK tracking */
    guint32      ack_frame_id;  /* ID of ACKing frame */
    wmem_list_t *ack_list;      /* Acknowledgement list. Used by ACK frames to store IDs. */
    gboolean     is_acked;      /* Was this frame acked? */
    gboolean     is_ack;        /* Is this an ACK frame? */
    gboolean     is_keepalive;  /* Is this a keep alive? */
    nstime_t     ack_time;      /* Acknowledgement time */
} btp_transmission_t;

/* Name:
 *      btp_frame_data_t
 * Purpose:
 *      Structure holding frame data for handshake and ACK tracking
 *
 */
typedef struct
{
    guint32    frame_id;           /* ID of associated frame with this data */
    address    frame_src_address;  /* Source address of this frame */
    address    frame_dst_address;  /* Destination address of this frame */
    guint8     frame_type;         /* Frame type: handshake or transmission */

    struct
    {
        gboolean timed_out;     /* Handshake or ACK timed out */
        gboolean unknown;       /* Unknown error */
        gboolean no_response;   /* Handshake request received no reponse before data was sent */
        gboolean missing;       /* Missing sequence number */
    } error;

    union {
        /* Frame type - handshake */
        /* Purpose: Req/res tracking*/
        btp_handshake_t    *handshake;

        /* Frame type - data/ACK */
        /* Purpose: ACK tracking and reassembly */
        btp_transmission_t *transmission;
    } data;
} btp_frame_data_t;

/* Name:
 *       btp_message_data_t
 *  Purpose:
 *       Store message data for error checking
 */
typedef struct
{
    address  source_address;        /* Message source address */
    guint32  message_id;            /* Message ID */
    guint16  data_length;           /* Message data length */
    guint8   segment_count;         /* Message segment count */
    gboolean is_complete;           /* Flag indicating that last message segment was received */
} btp_message_data_t;

/* Name:
 *       btp_conv_info_t
 *  Purpose:
 *       Conversation information. Stores all unfinished, finished frame data and message data.
 *       Maintains data_message_id and data_segment_id counter to uniquely identify messages for reassembly
 */
typedef struct
{
    wmem_list_t *processed_frame_data;  /* Stack holding unfinished frame data */
    wmem_tree_t *ready_frame_data;      /* Tree holding finished frame data */
    wmem_tree_t *message_data;          /* Tree holding message data */
    guint32      data_message_id;       /* Conversation specific data message ID (needed for reassembly) */
} btp_conv_info_t;

/* Dissector handles */
static dissector_handle_t wpan_dissector_handle;

/* Reassembly table handle */
static reassembly_table btp_reassembly_table;

#define MASKBIT(sh) (1<<sh)

/* BTP opcode values */
#define BTP_OPCODE_HANDSHAKE    0x6c

/* Flags */
#define BTP_HEADER_BEGINNING_SEGMENT_FLAG_MASK     MASKBIT(0)
#define BTP_HEADER_CONTINUE_SEGMENT_FLAG_MASK      MASKBIT(1)
#define BTP_HEADER_ENDING_SEGMENT_FLAG_MASK        MASKBIT(2)
#define BTP_HEADER_ACKNOWLEDGEMENT_FLAG_MASK       MASKBIT(3)
#define BTP_HEADER_MANAGEMENT_MESSAGE_FLAG_MASK    MASKBIT(5)
#define BTP_HEADER_HANDSHAKE_FLAG_MASK             MASKBIT(6)
#define BTP_HEADER_RESERVED_1_FLAG_MASK            MASKBIT(4)
#define BTP_HEADER_RESERVED_2_FLAG_MASK            MASKBIT(7)

/* BTP handshake header value */
#define BTP_HANDSHAKE (BTP_HEADER_HANDSHAKE_FLAG_MASK | BTP_HEADER_MANAGEMENT_MESSAGE_FLAG_MASK | 0x0e)

/* BTP data header value */
#define BTP_DATA_FRAME (BTP_HEADER_BEGINNING_SEGMENT_FLAG_MASK  \
                      | BTP_HEADER_CONTINUE_SEGMENT_FLAG_MASK   \
                      | BTP_HEADER_ENDING_SEGMENT_FLAG_MASK)

/* BTP field sizes */
#define BTP_HEADER_SIZE                 sizeof(guint8)
#define BTP_MANAGEMENT_OPCODE_SIZE      sizeof(guint8)
#define BTP_ACKNOWLEDGEMENT_NUMBER_SIZE sizeof(guint8)
#define BTP_SEQUENCE_NUMBER_SIZE        sizeof(guint8)
#define BTP_MESSAGE_LENGTH_SIZE         sizeof(guint16)
#define BTP_OBSERVED_ATT_MTU_SIZE       sizeof(guint16)
#define BTP_CLIENT_WINDOW_SIZE          sizeof(guint8)
#define BTP_SELECTED_VERSION_SIZE       sizeof(guint8)
#define BTP_SELECTED_SEGMENT_SIZE       sizeof(guint8)
#define BTP_SELECTED_WINDOW_SIZE        sizeof(guint8)
#define BTP_SUPPORTED_VERSION_SIZE      sizeof(guint32)
#define BTP_VERSION_NIBBLE_SIZE         sizeof(guint8)

#define BTP_FRAME_TYPE_HANDSHAKE    1
#define BTP_FRAME_TYPE_TRANSMISSION 2

/* Protocol constants */
/* Timeouts in msec */
#define BTP_CONN_RSP_TIMEOUT_MS     5000        /* Connection response time out */
#define BTP_ACK_TIMEOUT_MS          15000       /* Acknowledgement time out */
#define BTP_CONN_IDLE_TIMEOUT_MS    120000      /* Idle connection time out */

/* BTATT definitions */
#define BTATT_OPCODE_WRITE_REQUEST             0x12
#define BTATT_OPCODE_HANDLE_VALUE_INDICATION   0x1d

/* Protocol and registered fields */
static int proto_btp = -1;

/* BTP header flags */
static int hf_btp_header = -1;
static int hf_btp_beginning_flag = -1;
static int hf_btp_continue_segment_flag = -1;
static int hf_btp_ending_segment_flag = -1;
static int hf_btp_acknowledgement_flag = -1;
static int hf_btp_management_message_flag = -1;
static int hf_btp_handshake_flag = -1;
static int hf_btp_reserved_1_flag = -1;
static int hf_btp_reserved_2_flag = -1;

/* BTP fields */
static int hf_btp_management_opcode = -1;
static int hf_btp_acknowledgement_number = -1;
static int hf_btp_sequence_number = -1;
static int hf_btp_message_length = -1;
static int hf_btp_message_id = -1;
static int hf_btp_segment_id = -1;
static int hf_btp_supported_versions = -1;
static int hf_btp_version = -1;
static int hf_btp_observed_att_mtu = -1;
static int hf_btp_client_window_size = -1;
static int hf_btp_selected_version = -1;
static int hf_btp_selected_segment_size = -1;
static int hf_btp_selected_window_size = -1;
static int hf_btp_payload = -1;

/* Payload reassembly fields */
static int hf_btp_fragments = -1;
static int hf_btp_fragment = -1;
static int hf_btp_fragment_overlap = -1;
static int hf_btp_fragment_overlap_conflicts = -1;
static int hf_btp_fragment_multiple_tails = -1;
static int hf_btp_fragment_too_long_fragment = -1;
static int hf_btp_fragment_error = -1;
static int hf_btp_fragment_count = -1;
static int hf_btp_reassembled_in = -1;
static int hf_btp_reassembled_length = -1;
static int hf_btp_reassembled_data = -1;

/* Handshake request/response fields */
static int hf_btp_response_in = -1;
static int hf_btp_response_to = -1;
static int hf_btp_response_time = -1;

/* Acknowledgement tracking */
static int hf_btp_acked_by = -1;
static int hf_btp_acks_tree = -1;
static int hf_btp_ack = -1;
static int hf_btp_ack_time = -1;

/* Initialize the subtree pointers */
static gint ett_btp = -1;
static gint ett_btp_version = -1;
static gint ett_btp_fragment = -1;
static gint ett_btp_fragments = -1;
static gint ett_btp_acknowledgements = -1;
static gint ett_btp_header = -1;

/* Expert info fields */
static expert_field ei_btp_data_length_invalid  = EI_INIT;
static expert_field ei_btp_keep_alive = EI_INIT;
static expert_field ei_btp_ack_timeout = EI_INIT;
static expert_field ei_btp_handshake_timeout = EI_INIT;
static expert_field ei_btp_handshake_unknown_error = EI_INIT;
static expert_field ei_btp_handshake_request_missing = EI_INIT;
static expert_field ei_btp_data_message_empty = EI_INIT;

/* Header bit fields */
static const int *hfx_btp_header_bit_fields[] =
{
    &hf_btp_reserved_2_flag,
    &hf_btp_handshake_flag,
    &hf_btp_management_message_flag,
    &hf_btp_reserved_1_flag,
    &hf_btp_acknowledgement_flag,
    &hf_btp_ending_segment_flag,
    &hf_btp_continue_segment_flag,
    &hf_btp_beginning_flag,
    NULL
};

/* Reassembly fields */
static const fragment_items btp_frag_items =
{
    /* Fragment subtrees */
    &ett_btp_fragment,
    &ett_btp_fragments,
    /* Fragment fields */
    &hf_btp_fragments,
    &hf_btp_fragment,
    &hf_btp_fragment_overlap,
    &hf_btp_fragment_overlap_conflicts,
    &hf_btp_fragment_multiple_tails,
    &hf_btp_fragment_too_long_fragment,
    &hf_btp_fragment_error,
    &hf_btp_fragment_count,
    /* Reassembled in field */
    &hf_btp_reassembled_in,
    /* Reassembled length field */
    &hf_btp_reassembled_length,
    /* Reassembled data */
    &hf_btp_reassembled_data,
    /* Tag */
    "BTP WPAN fragments"
};

static const value_string btp_opcode_values[] =
{
    { BTP_OPCODE_HANDSHAKE, "BTP handshake request or response" },
    { 0,                    NULL }, /* value_string terminator */
};

/* Name
 *       btp_process_handshake
 *
 *  Parameters:
 *       pinfo           -       packet information
 *       btp_tree        -       BTP dissection tree
 *       tvb             -       buffer to be dissected
 *       offset          -       dissection offset
 *       main_item       -       main tree item
 *       btp_conv_info   -       conversation data
 *
 *  Return value:
 *       Offset after dissection
 *
 *  Purpose:
 *       This function sets up tracking data structures for handshake request/response and displays data
 *
 */
static guint
btp_process_handshake(packet_info *pinfo, proto_tree *btp_tree, tvbuff_t *tvb, guint offset,
    proto_item *main_item, btp_conv_info_t *btp_conv_info, btatt_data_t *btatt_data)
{
    proto_item       *ti;                           /* Temporary protocol item */
    proto_tree       *btp_version_tree;             /* BTP protocol version tree */
    btp_frame_data_t *btp_frame_data = NULL;        /* This frame data */
    btp_frame_data_t *btp_prev_frame_data = NULL;   /* Previous frame data */
    guint8            btp_version_nibbles;          /* BTP protocol version nibbles */

    /* Check if frame was already visited */
    if (pinfo->fd->flags.visited == FALSE)
    {
        /* Allocate new data structure and assign frame data */
        btp_frame_data = wmem_new(wmem_file_scope(), btp_frame_data_t);

        btp_frame_data->frame_id = pinfo->num;
        btp_frame_data->frame_src_address = pinfo->dl_src;
        btp_frame_data->frame_dst_address = pinfo->dl_dst;
        btp_frame_data->frame_type = BTP_FRAME_TYPE_HANDSHAKE;

        btp_frame_data->error.timed_out = FALSE;
        btp_frame_data->error.no_response = FALSE;
        btp_frame_data->error.missing = FALSE;
        btp_frame_data->error.unknown = FALSE;

        /* Check if stack is empty (wmem_stack_peek throws exception if stack is empty) */
        if (wmem_stack_count(btp_conv_info->processed_frame_data) != 0)
        {
            /* Take pointer to previous frame data */
            btp_prev_frame_data = (btp_frame_data_t*)wmem_stack_peek(btp_conv_info->processed_frame_data);
        }

        /* Check if write request */
        if (btatt_data->opcode == BTATT_OPCODE_WRITE_REQUEST)
        {
            /* This is a handshake request */
            /* Allocate new handshake structure */
            btp_frame_data->data.handshake = wmem_new(wmem_file_scope(), btp_handshake_t);

            /* Fill handshake structure with inital values */
            btp_frame_data->data.handshake->req_frame_id = pinfo->num;
            btp_frame_data->data.handshake->rsp_frame_id = 0;                /* Shall be filled by response frame */
            btp_frame_data->data.handshake->rsp_time = pinfo->fd->abs_ts;    /* Shall be updated by response frame */

            /* Push to stack of unfinished frame data structures */
            wmem_stack_push(btp_conv_info->processed_frame_data, btp_frame_data);
        }
        else if (btatt_data->opcode == BTATT_OPCODE_HANDLE_VALUE_INDICATION)
        {
            /* This is a connection response */
            nstime_t delta;

            if ((btp_prev_frame_data == NULL) || (btp_prev_frame_data->frame_type != BTP_FRAME_TYPE_HANDSHAKE))
            {
                /* Handshake request is missing */
                btp_frame_data->error.missing = TRUE;
            }
            else
            {
                /* Found handshake request */
                btp_frame_data->data.handshake = btp_prev_frame_data->data.handshake;

                /* Check if previous handshake request timed out */
                nstime_delta(&delta, &pinfo->fd->abs_ts, &btp_prev_frame_data->data.handshake->rsp_time);
                /* Check for timeout */
                if (nstime_to_msec(&delta) > BTP_CONN_RSP_TIMEOUT_MS)
                {
                    /* Request timed out */
                    btp_prev_frame_data->error.timed_out = TRUE;
                    btp_frame_data->error.missing = TRUE;
                }
                else
                {
                    /* Calculate time delta between request and response */
                    nstime_delta(&delta, &pinfo->fd->abs_ts, &btp_frame_data->data.handshake->rsp_time);

                    /* Fill missing data */
                    btp_frame_data->data.handshake->rsp_frame_id = pinfo->num;
                    btp_frame_data->data.handshake->rsp_time = delta;

                    /* Remove completed frame data from stack */
                    wmem_stack_pop(btp_conv_info->processed_frame_data);
                }
            }
        }
        /* Insert frame data into tree under request and response frame IDs for easy lookup */
        wmem_tree_insert32(
            btp_conv_info->ready_frame_data,
            btp_frame_data->frame_id,
            btp_frame_data);
    }

    /* Look up frame data */
    btp_frame_data = (btp_frame_data_t*)wmem_tree_lookup32(btp_conv_info->ready_frame_data, pinfo->num);
    /* Check if frame data was found and if it is a handshake frame */
    if ((btp_frame_data != NULL) && (btp_frame_data->frame_type == BTP_FRAME_TYPE_HANDSHAKE))
    {
        if (btatt_data->opcode == BTATT_OPCODE_WRITE_REQUEST)
        {
            /* This is a connection request */
            guint8 i = 0;
            guint8 nibble = 0;

            /* Add subtree for version values */
            ti = proto_tree_add_item(btp_tree, hf_btp_supported_versions, tvb, offset, BTP_SUPPORTED_VERSION_SIZE, ENC_LITTLE_ENDIAN);
            btp_version_tree = proto_item_add_subtree(ti, ett_btp_version);

            /* Iterate over version nibbles and display them */
            for (i = 0; i < BTP_SUPPORTED_VERSION_SIZE; ++i)
            {
                btp_version_nibbles = tvb_get_guint8(tvb, offset);

                nibble = (btp_version_nibbles & 0xf0) >> 4;
                proto_tree_add_uint(btp_version_tree, hf_btp_version, tvb, offset, BTP_VERSION_NIBBLE_SIZE, nibble);
                nibble = btp_version_nibbles & 0x0f;
                proto_tree_add_uint(btp_version_tree, hf_btp_version, tvb, offset, BTP_VERSION_NIBBLE_SIZE, nibble);

                offset += sizeof(btp_version_nibbles);
            }

            /* Display ATT_MTU size */
            proto_tree_add_item(btp_tree, hf_btp_observed_att_mtu, tvb, offset, BTP_OBSERVED_ATT_MTU_SIZE, ENC_LITTLE_ENDIAN);
            offset += BTP_OBSERVED_ATT_MTU_SIZE;

            /* Display client windows size */
            proto_tree_add_item(btp_tree, hf_btp_client_window_size, tvb, offset, BTP_CLIENT_WINDOW_SIZE, ENC_LITTLE_ENDIAN);
            offset += BTP_CLIENT_WINDOW_SIZE;

            if (btp_frame_data->error.timed_out == TRUE)
            {
                expert_add_info(pinfo, main_item, &ei_btp_handshake_timeout);
            }
            else
            {
                /* Display response frame reference */
                ti = proto_tree_add_uint(btp_tree, hf_btp_response_in, tvb, 0, 0, btp_frame_data->data.handshake->rsp_frame_id);
                PROTO_ITEM_SET_GENERATED(ti);

                /* Display response time */
                ti = proto_tree_add_time(btp_tree, hf_btp_response_time, tvb, 0, 0, &btp_frame_data->data.handshake->rsp_time);
                PROTO_ITEM_SET_GENERATED(ti);

                /* Set info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, "Handshake request, response in frame %d", btp_frame_data->data.handshake->rsp_frame_id);
            }

            if (btp_frame_data->error.unknown == TRUE)
            {
                expert_add_info(pinfo, main_item, &ei_btp_handshake_unknown_error);
            }
        }
        else if (btatt_data->opcode == BTATT_OPCODE_HANDLE_VALUE_INDICATION)
        {
            /* This is a connection response */
            /* Display selected version */
            proto_tree_add_item(btp_tree, hf_btp_selected_version, tvb, offset, BTP_SELECTED_VERSION_SIZE, ENC_LITTLE_ENDIAN);
            offset += BTP_SELECTED_VERSION_SIZE;

            /* Display selected segment size */
            proto_tree_add_item(btp_tree, hf_btp_selected_segment_size, tvb, offset, BTP_SELECTED_SEGMENT_SIZE, ENC_LITTLE_ENDIAN);
            offset += BTP_SELECTED_SEGMENT_SIZE + 1;

            /* Display selected windows size */
            proto_tree_add_item(btp_tree, hf_btp_selected_window_size, tvb, offset, BTP_SELECTED_WINDOW_SIZE, ENC_LITTLE_ENDIAN);
            offset += BTP_SELECTED_WINDOW_SIZE;

            if (btp_frame_data->error.missing == TRUE)
            {
                /* Handshake request is missing */
                expert_add_info(pinfo, main_item, &ei_btp_handshake_request_missing);
                col_append_str(pinfo->cinfo, COL_INFO, "Handshake response, request is missing");
            }
            else
            {
                /* Display request frame reference */
                ti = proto_tree_add_uint(btp_tree, hf_btp_response_to, tvb, 0, 0, btp_frame_data->data.handshake->req_frame_id);
                PROTO_ITEM_SET_GENERATED(ti);

                /* Display response time */
                ti = proto_tree_add_time(btp_tree, hf_btp_response_time, tvb, 0, 0, &btp_frame_data->data.handshake->rsp_time);
                PROTO_ITEM_SET_GENERATED(ti);

                /* Set info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, "Handshake response, request in frame %d", btp_frame_data->data.handshake->req_frame_id);
            }
        }
    }
    return offset;
}

/* Name:
 *       btp_process_acknowledgement
 *
 *  Parameters:
 *       pinfo           -       packet information
 *       btp_tree        -       BTP dissection tree
 *       tvb             -       buffer to be dissected
 *       offset          -       dissection offset
 *       main_item       -       main tree item
 *       btp_conv_info   -       conversation data
 *       btp_frame_data  -       data of frame to be processed
 *
 *  Return value:
 *       Offset after dissection
 *
 *  Purpose:
 *       This function sets up tracking data structures for ACK and displays data
 *
 */
static guint
btp_process_acknowledgement(packet_info *pinfo, proto_tree *btp_tree,
    tvbuff_t *tvb, guint offset, proto_item *main_item, btp_conv_info_t *btp_conv_info,
    btp_frame_data_t *btp_frame_data, guint btp_header)
{
    proto_item       *ti;                           /* Temporary protocol item */
    guint8            btp_acknowledgement_number;   /* Acknowledgement number */
    btp_frame_data_t *btp_prev_frame_data;          /* Previous frame data */

    /* Get acknowledgement number */
    btp_acknowledgement_number = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(btp_tree, hf_btp_acknowledgement_number, tvb, offset, BTP_ACKNOWLEDGEMENT_NUMBER_SIZE, ENC_LITTLE_ENDIAN);
    offset += BTP_ACKNOWLEDGEMENT_NUMBER_SIZE;

    if (pinfo->fd->flags.visited == FALSE)
    {
        /* Acknowledgement frame. Find acknowledged frames and remove thier data from stack */
        wmem_stack_t *temp_stack;
        gboolean      found_frame = FALSE;
        nstime_t      delta;

        temp_stack = wmem_stack_new(NULL); /* Allocate temporary stack in global pool */

        /* Set ACK data for this frame */
        btp_frame_data->data.transmission->is_ack = TRUE;
        btp_frame_data->data.transmission->btp_ack_number = btp_acknowledgement_number;
        btp_frame_data->data.transmission->ack_list = wmem_list_new(wmem_file_scope());

        if ((wmem_stack_count(btp_conv_info->processed_frame_data) == 0) && ((btp_header & BTP_DATA_FRAME) == FALSE))
        {
            /* This is likely a keep alive frame */
            btp_frame_data->data.transmission->is_keepalive = TRUE;
        }
        else if (wmem_stack_count(btp_conv_info->processed_frame_data) == 1)
        {
            /* This is a keep alive frame */
            btp_prev_frame_data = (btp_frame_data_t*)wmem_stack_peek(btp_conv_info->processed_frame_data);
            if ((btp_prev_frame_data->data.transmission->is_ack == TRUE) && ((btp_header & BTP_DATA_FRAME) == FALSE))
            {
                /* This is a keepalive frame */
                btp_frame_data->data.transmission->is_keepalive = TRUE;
            }
        }
        /* Iterate over all frames */
        while (wmem_stack_count(btp_conv_info->processed_frame_data) != 0)
        {
            btp_prev_frame_data = (btp_frame_data_t*)wmem_stack_pop(btp_conv_info->processed_frame_data);

            /* Found past frame */
            if (btp_prev_frame_data->frame_type == BTP_FRAME_TYPE_HANDSHAKE)
            {
                /* Warning: handshake must be completed before sending any data. Perhaps a handshake frame is missing */
                btp_prev_frame_data->error.missing = TRUE;
            }
            else if ((btp_prev_frame_data->data.transmission->btp_sequence_number != btp_frame_data->data.transmission->btp_ack_number) &&
                (found_frame == FALSE))
            {
                wmem_stack_push(temp_stack, btp_prev_frame_data);
            }
            else
            {
                /* Ensure the addresses match to avoid ACK-ing frames sent by the same device */
                if (addresses_equal(&btp_prev_frame_data->frame_src_address, &btp_frame_data->frame_dst_address) == FALSE)
                {
                    wmem_stack_push(temp_stack, btp_prev_frame_data);
                }
                else
                {
                    /* Found frame to acknowledge */
                    /* Acknowledge all past frames to this one */
                    found_frame = TRUE;

                    /* Calculate time delta */
                    nstime_delta(&delta, &pinfo->fd->abs_ts, &btp_prev_frame_data->data.transmission->ack_time);
                    if (nstime_to_msec(&delta) > BTP_ACK_TIMEOUT_MS)
                    {
                        /* Timed out */
                        btp_prev_frame_data->error.timed_out = TRUE;
                    }
                    else
                    {
                        /* Fill missing data for previous frame */
                        btp_prev_frame_data->data.transmission->is_acked = TRUE;
                        btp_prev_frame_data->data.transmission->ack_frame_id = pinfo->num;
                        btp_prev_frame_data->data.transmission->ack_time = delta;

                        /* Store pointer to ACKed frame data in list */
                        wmem_list_prepend(btp_frame_data->data.transmission->ack_list, btp_prev_frame_data);
                    }
                }
            }
        }
        while (wmem_stack_count(temp_stack) != 0)
        {
            /* Restore unfinished frame data stack */
            btp_prev_frame_data = (btp_frame_data_t*)wmem_stack_pop(temp_stack);
            wmem_stack_push(btp_conv_info->processed_frame_data, btp_prev_frame_data);
        }
        /* Deallocate temporary stack */
        wmem_destroy_stack(temp_stack);
    }

    /* Display information */
    /* Check if list is empty. This might happen for keepalive frames after handshake. */
    if (wmem_list_count(btp_frame_data->data.transmission->ack_list) != 0)
    {
        wmem_list_frame_t *frame = NULL;
        proto_tree        *ack_tree = NULL;
        proto_item        *ack_item;

        /* Create tree for ID of acknowledged frames by this packet */
        ack_item = proto_tree_add_item(btp_tree, hf_btp_acks_tree, tvb, 0, 0, ENC_LITTLE_ENDIAN);
        ack_tree = proto_item_add_subtree(ack_item, ett_btp_acknowledgements);
        PROTO_ITEM_SET_GENERATED(ack_item);

        /* Iterate over ack list elements */
        frame = wmem_list_head(btp_frame_data->data.transmission->ack_list);
        col_append_str(pinfo->cinfo, COL_INFO, "ACKed seq: ");

        while (frame != NULL)
        {
            /* Get ID of acked frame */
            btp_prev_frame_data = (btp_frame_data_t*)wmem_list_frame_data(frame);
            /* Display ack ID */
            ti = proto_tree_add_uint(ack_tree, hf_btp_ack, tvb, 0, 0, btp_prev_frame_data->frame_id);
            PROTO_ITEM_SET_GENERATED(ti);

            /* Append frame number to tree text */
            proto_item_append_text(ack_item, " #%u(%u)", btp_prev_frame_data->data.transmission->btp_sequence_number, btp_prev_frame_data->frame_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, "#%u", btp_prev_frame_data->data.transmission->btp_sequence_number);
            if(wmem_list_frame_next(frame) != NULL)
            {
                proto_item_append_text(ack_item, ",");
                col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, " ");
            }
            /* Next element */
            frame = wmem_list_frame_next(frame);
        }
    }

    /* Is this a keepalive frame? */
    if (btp_frame_data->data.transmission->is_keepalive == TRUE)
    {
        /* Display keepalive info */
        expert_add_info(pinfo, main_item, &ei_btp_keep_alive);
        col_append_str(pinfo->cinfo, COL_INFO, "Keep-alive ");
    }
    /* Return offset after dissection */
    return offset;
}

/* Name:
 *       btp_process_data_frame
 *
 *  Parameters:
 *       pinfo           -       packet information
 *       tree            -       main dissection tree
 *       btp_tree        -       BTP dissection tree
 *       tvb             -       buffer to be dissected
 *       offset          -       dissection offset
 *       btp_conv_info   -       conversation data
 *       btp_frame_data  -       data of frame to be processed
 *       btp_header      -       BTP header value
 *
 *  Return value:
 *       Offset after dissection
 *
 *  Purpose:
 *       This function reassembles payload and displays data
 */
static guint
btp_process_data_frame(packet_info *pinfo, proto_tree *tree, proto_tree *btp_tree,
    tvbuff_t *tvb, guint offset, proto_item *main_item, btp_conv_info_t *btp_conv_info,
    btp_frame_data_t *btp_frame_data, guint btp_header)
{
    proto_item         *ti;                      /* Temporary protocol item */
    guint16             btp_message_length;      /* BTP message length */
    guint16             btp_payload_length;      /* Payload length of a single BTP frame */
    gboolean            save_fragmented = FALSE; /* Variable to store pinfo reassembly state */
    fragment_head      *head = NULL;             /* Fragment data */
    tvbuff_t           *new_tvb = NULL;          /* Storage buffer for reassembled payload */
    btp_message_data_t *btp_message_data = NULL; /* Message data */

    if (btp_header & BTP_HEADER_BEGINNING_SEGMENT_FLAG_MASK)
    {
        /* Beginning segment. Get full data length */
        btp_message_length = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(btp_tree, hf_btp_message_length, tvb, offset, BTP_MESSAGE_LENGTH_SIZE, ENC_LITTLE_ENDIAN);
        offset += BTP_MESSAGE_LENGTH_SIZE;
    }

    /* Check if frame was already visited */
    if (pinfo->fd->flags.visited == FALSE)
    {
        /* Set btp_frame_info data */
        if (btp_header & BTP_HEADER_BEGINNING_SEGMENT_FLAG_MASK)
        {
            /* Allocate new message data and set segment and message IDs */
            /* Increment message ID (reassembly values) */
            btp_conv_info->data_message_id++;

            /* Allocate message data and save data length obtained from beginning frame */
            btp_message_data = wmem_new(wmem_file_scope(), btp_message_data_t);
            btp_message_data->data_length    = btp_message_length;
            btp_message_data->source_address = pinfo->dl_src;
            btp_message_data->message_id     = btp_conv_info->data_message_id;
            btp_message_data->segment_count  = 1;
            btp_message_data->is_complete    = btp_header & BTP_HEADER_ENDING_SEGMENT_FLAG_MASK;
            /* Insert into message data tree */
            wmem_tree_insert32(btp_conv_info->message_data, btp_conv_info->data_message_id, btp_message_data);

            /* Assign message and segment IDs to frame data for later lookup */
            btp_frame_data->data.transmission->data_message_id = btp_conv_info->data_message_id;
            btp_frame_data->data.transmission->data_segment_id = 0;
        }
        else
        {
            /* Iterate over previous messages to find incompleted message sent from this address */
            for(guint32 i = btp_conv_info->data_message_id; i != 0; i--)
            {
                /* Get message data */
                btp_message_data = (btp_message_data_t*)wmem_tree_lookup32(
                    btp_conv_info->message_data, i);
                if((btp_message_data != NULL)
                    && (addresses_equal(&btp_message_data->source_address, &pinfo->dl_src) == TRUE)
                    && (btp_message_data->is_complete == FALSE))
                {
                    /* Found incompleted message */
                    /* Add this message data to frame data */
                    btp_frame_data->data.transmission->data_message_id = btp_message_data->message_id;
                    btp_frame_data->data.transmission->data_segment_id = btp_message_data->segment_count;

                    btp_message_data->segment_count++;
                    btp_message_data->is_complete = btp_header & BTP_HEADER_ENDING_SEGMENT_FLAG_MASK;
                    break;
                }
            }
        }
    }
    /* Check if payload is empty */
    btp_payload_length = tvb_captured_length_remaining(tvb, offset);
    if(btp_payload_length == 0)
    {
        /* Display warning if the frame payload is empty */
        col_append_str(pinfo->cinfo, COL_INFO, "Empty data frame!");
        expert_add_info(pinfo, main_item, &ei_btp_data_message_empty);
    }
    else
    {
        /* Get message data */
        btp_message_data = (btp_message_data_t*)wmem_tree_lookup32(
            btp_conv_info->message_data,
            btp_frame_data->data.transmission->data_message_id);

        /* Display information */
        col_append_str(pinfo->cinfo, COL_INFO, "Data");
        /* Display fragment info */
        col_append_fstr(pinfo->cinfo, COL_INFO, " msg:#%u ", btp_frame_data->data.transmission->data_message_id);
        if ((btp_message_data != NULL) && (btp_message_data->segment_count > 1))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "seg:#%u", btp_frame_data->data.transmission->data_segment_id);
        }
        ti = proto_tree_add_uint(btp_tree, hf_btp_message_id, tvb, 0, 0, btp_frame_data->data.transmission->data_message_id);
        PROTO_ITEM_SET_GENERATED(ti);
        ti = proto_tree_add_uint(btp_tree, hf_btp_segment_id, tvb, 0, 0, btp_frame_data->data.transmission->data_segment_id+1);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Save fragmented state */
        save_fragmented = pinfo->fragmented;

        /* Reassemble data */
        /* Add next fragment and check if ready */
        head = fragment_add_seq_check(
            &btp_reassembly_table,
            tvb, offset, pinfo,
            btp_frame_data->data.transmission->data_message_id, NULL,
            btp_frame_data->data.transmission->data_segment_id,
            btp_payload_length,
            !(btp_header & BTP_HEADER_ENDING_SEGMENT_FLAG_MASK));

        new_tvb = process_reassembled_data(
            tvb, offset, pinfo,
            "Reassembled WPAN",
            head, &btp_frag_items,
            NULL, btp_tree);

        if (new_tvb)
        {
            /* Data was successfully reassembled */
            /* Check if length matches */
            if ((btp_message_data != NULL) && (btp_message_data->data_length != tvb_reported_length(new_tvb)))
            {
                /* Lengths do not match. Display warning. */
                ti = proto_tree_add_item(btp_tree, hf_btp_reassembled_length, new_tvb, 0, -1, ENC_LITTLE_ENDIAN);
                expert_add_info(pinfo, ti, &ei_btp_data_length_invalid);
            }

            /* Call WPAN dissector on reassembled data. */
            call_dissector(wpan_dissector_handle, new_tvb, pinfo, tree);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", sent through BTP");
        }
        proto_tree_add_item(btp_tree, hf_btp_payload, tvb, offset, -1, ENC_NA);

        /* Restore fragmented state */
        pinfo->fragmented = save_fragmented;
    }

    return tvb_captured_length(tvb);
}

/* Name:
 *       btp_process_transmission
 *
 *  Parameters:
 *       pinfo           -       packet information
 *       tree            -       main protocol tree
 *       btp_tree        -       BTP dissection tree
 *       tvb             -       buffer to be dissected
 *       offset          -       dissection offset
 *       main_item       -       protocol main item
 *       btp_conv_info   -       conversation data
 *       btp_header      -       BTP header value
 *
 *  Return value:
 *       Offset after dissection
 *
 *  Purpose:
 *       Process data and/or ACK frames and display data common to both
 */
static guint
btp_process_transmission(packet_info *pinfo, proto_tree *tree, proto_tree *btp_tree,
    tvbuff_t *tvb, guint offset, proto_item *main_item, btp_conv_info_t *btp_conv_info,
    guint btp_header)
{
    /* Temporary protocol item */
    proto_item *ti;

    /* This frame data */
    btp_frame_data_t *btp_frame_data = NULL;

    /* Check if frame was already visited */
    if (pinfo->fd->flags.visited == FALSE)
    {
        /* Allocate and fill btp_frame_data */
        btp_frame_data = wmem_new(wmem_file_scope(), btp_frame_data_t);

        /* Default values */
        btp_frame_data->frame_id = pinfo->num;
        btp_frame_data->frame_src_address = pinfo->dl_src;
        btp_frame_data->frame_dst_address = pinfo->dl_dst;
        btp_frame_data->frame_type = BTP_FRAME_TYPE_TRANSMISSION;

        btp_frame_data->data.transmission = wmem_new(wmem_file_scope(), btp_transmission_t);
        btp_frame_data->data.transmission->ack_time = pinfo->fd->abs_ts;
        btp_frame_data->data.transmission->btp_sequence_number = 0;
        btp_frame_data->data.transmission->is_acked = FALSE;
        btp_frame_data->data.transmission->is_ack = FALSE;
        btp_frame_data->data.transmission->is_keepalive = FALSE;
        btp_frame_data->data.transmission->ack_list = NULL;
        btp_frame_data->data.transmission->ack_frame_id = 0;
        btp_frame_data->data.transmission->data_message_id = 0;
        btp_frame_data->data.transmission->data_segment_id = 0;
    }
    else
    {
        /* Get frame data associated with this frame */
        btp_frame_data = (btp_frame_data_t*)wmem_tree_lookup32(btp_conv_info->ready_frame_data, pinfo->num);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Frame seq:#%u, ", btp_frame_data->data.transmission->btp_sequence_number);
    }

    /* Data and/or ACK frame */
    if (btp_header & BTP_HEADER_ACKNOWLEDGEMENT_FLAG_MASK)
    {
        offset = btp_process_acknowledgement(
            pinfo, btp_tree, tvb, offset, main_item,
            btp_conv_info, btp_frame_data, btp_header
        );
    }

    if (btp_frame_data->error.timed_out)
    {
        /* Frame ACK timed out */
        expert_add_info(pinfo, main_item, &ei_btp_ack_timeout);
    }
    else
    {
        /* Display ACK tracking information */
        if (btp_frame_data->data.transmission->is_acked == TRUE)
        {
            /* Display ID of acking frame */
            ti = proto_tree_add_uint(btp_tree, hf_btp_acked_by, tvb, 0, 0, btp_frame_data->data.transmission->ack_frame_id);
            PROTO_ITEM_SET_GENERATED(ti);
            /* Display ACK time */
            ti = proto_tree_add_time(btp_tree, hf_btp_ack_time, tvb, 0, 0, &btp_frame_data->data.transmission->ack_time);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    /* Frame sequence number */
    if (pinfo->fd->flags.visited == FALSE)
    {
        btp_frame_data->data.transmission->btp_sequence_number = tvb_get_guint8(tvb, offset);

        /* Push this info to unfinished frame data stack and data tree */
        wmem_stack_push(btp_conv_info->processed_frame_data, btp_frame_data);
        wmem_tree_insert32(btp_conv_info->ready_frame_data, btp_frame_data->frame_id, btp_frame_data);
    }
    /* Display sequence number */
    proto_tree_add_item(btp_tree, hf_btp_sequence_number, tvb, offset, BTP_SEQUENCE_NUMBER_SIZE, ENC_LITTLE_ENDIAN);
    offset += BTP_SEQUENCE_NUMBER_SIZE;

    if (btp_header & BTP_DATA_FRAME)
    {
        offset = btp_process_data_frame(
            pinfo, tree, btp_tree, tvb, offset, main_item,
            btp_conv_info, btp_frame_data, btp_header
        );
    }

    return offset;
}


/* Name:
 *      dissect_btp
 *
 *  Parameters:
 *      tvb     -   buffer to be dissected
 *      pinfo   -   packet info
 *      tree    -   protocol tree
 *      data    -   packet
 *
 *  Return value:
 *      int     -   length of dissected data or 0 if not BTP
 *
 *  Purpose:
 *      Dissection procedure for BTP
 */
static int
dissect_btp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Tree variables */
    proto_item *main_item;
    proto_tree *btp_tree;

    /* Header variables */
    proto_item *header_item;
    proto_tree *header_tree;

    proto_tree *parent_item = NULL;
    proto_item *parent_tree = NULL;

    /* Dissection buffer offset */
    guint offset = 0;

    /* BTP variables */
    guint8 btp_header = 0;

    /* Conversation variables */
    /* Needed for request/response and ACK tracking */
    conversation_t   *conversation = NULL;
    btp_conv_info_t  *btp_conv_info = NULL;
    btatt_data_t     *btatt_data = (btatt_data_t*)data;

    /* Get conversation data */
    conversation = find_or_create_conversation(pinfo);
    btp_conv_info = (btp_conv_info_t*)conversation_get_proto_data(conversation, proto_btp);
    if (btp_conv_info == NULL)
    {
        /* New conversation. Allocate and assign data structures. */
        btp_conv_info = wmem_new(wmem_file_scope(), btp_conv_info_t);
        btp_conv_info->processed_frame_data = wmem_stack_new(wmem_file_scope());
        btp_conv_info->ready_frame_data = wmem_tree_new(wmem_file_scope());
        btp_conv_info->message_data = wmem_tree_new(wmem_file_scope());
        btp_conv_info->data_message_id = 0;
        conversation_add_proto_data(conversation, proto_btp, btp_conv_info);
    }
    /* Get parent item and tree */
    parent_item = proto_tree_get_parent(tree);
    if(parent_item != NULL)
    {
        parent_tree = proto_item_get_parent(parent_item);
        tree = parent_tree;
    }
    /* Protocol tree */
    main_item = proto_tree_add_item(tree, proto_btp, tvb, 0, -1, ENC_NA);
    btp_tree = proto_item_add_subtree(main_item, ett_btp);

    /* Display protocol name */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BTP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* BTP header */
    btp_header = tvb_get_guint8(tvb, offset);
    header_item = proto_tree_add_item(btp_tree, hf_btp_header, tvb, offset, BTP_HEADER_SIZE, ENC_LITTLE_ENDIAN);
    header_tree = proto_item_add_subtree(header_item, ett_btp_header);

    proto_tree_add_bitmask_list(header_tree, tvb, offset, BTP_HEADER_SIZE, hfx_btp_header_bit_fields, ENC_NA);
    offset += BTP_HEADER_SIZE;

    if (btp_header & BTP_HEADER_MANAGEMENT_MESSAGE_FLAG_MASK)
    {
        /* Management opcode */
        tvb_get_guint8(tvb, offset);
        proto_tree_add_item(btp_tree, hf_btp_management_opcode, tvb, offset, BTP_MANAGEMENT_OPCODE_SIZE, ENC_LITTLE_ENDIAN);
        offset += BTP_MANAGEMENT_OPCODE_SIZE;
    }

    if (btp_header == BTP_HANDSHAKE)
    {
        /* Handshake request/response */
        offset = btp_process_handshake(
            pinfo, btp_tree, tvb, offset,
            main_item, btp_conv_info, btatt_data
        );
    }
    else
    {
        /* Data and/or ACK frame */
        offset = btp_process_transmission(
            pinfo, tree, btp_tree, tvb, offset,
            main_item, btp_conv_info, btp_header
        );
    }

    return tvb_captured_length(tvb);
}

/* Name:
 *       proto_register_btp
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
proto_register_btp(void)
{
    /* Expert module pointer */
    expert_module_t *expert_btp;

    /* Setup list of header fields. */
    static hf_register_info hf[] =
    {
        /* BTP fields */
        {
            &hf_btp_header,
            {
                "Header", "btp.header",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_beginning_flag,
            {
                "Beginning segment", "btp.header.begin_flag",
                FT_BOOLEAN, 8,
                NULL, BTP_HEADER_BEGINNING_SEGMENT_FLAG_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_btp_continue_segment_flag,
            {
                "Continue segment", "btp.header.continue_flag",
                FT_BOOLEAN, 8,
                NULL, BTP_HEADER_CONTINUE_SEGMENT_FLAG_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_btp_ending_segment_flag,
            {
                "Ending segment", "btp.header.end_flag",
                FT_BOOLEAN, 8,
                NULL, BTP_HEADER_ENDING_SEGMENT_FLAG_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_btp_acknowledgement_flag,
            {
                "Acknowledgement", "btp.header.ack_flag",
                FT_BOOLEAN, 8,
                NULL, BTP_HEADER_ACKNOWLEDGEMENT_FLAG_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_btp_management_message_flag,
            {
                "Management message", "btp.header.management_flag",
                FT_BOOLEAN, 8,
                NULL, BTP_HEADER_MANAGEMENT_MESSAGE_FLAG_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_btp_handshake_flag,
            {
                "Handshake", "btp.header.handshake_flag",
                FT_BOOLEAN, 8,
                NULL, BTP_HEADER_HANDSHAKE_FLAG_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_btp_reserved_1_flag,
            {
                "Reserved", "btp.header.reserved",
                FT_BOOLEAN, 8,
                NULL, BTP_HEADER_RESERVED_1_FLAG_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_btp_reserved_2_flag,
            {
                "Reserved", "btp.header.reserved",
                FT_BOOLEAN, 8,
                NULL, BTP_HEADER_RESERVED_2_FLAG_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_btp_management_opcode,
            {
                "Management opcode", "btp.opcode",
                FT_UINT8, BASE_HEX,
                VALS(btp_opcode_values), 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_acknowledgement_number,
            {
                "Acknowledgement number", "btp.ack_number",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_sequence_number,
            {
                "Sequence number", "btp.seq_number",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_message_length,
            {
                "Message length", "btp.data.length",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_message_id,
            {
                "Message ID", "btp.data.message_id",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_segment_id,
            {
                "Segment ID", "btp.data.segment_id",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_payload,
            {
                "Payload", "btp.data.payload",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_supported_versions,
            {
                "Supported BTP protocol versions", "btp.handshake.supported_versions",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_version,
            {
                "Value", "btp.handshake.supported_versions.value",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_observed_att_mtu,
            {
                "Observed ATT_MTU size", "btp.handshake.att_mtu",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_client_window_size,
            {
                "Client windows size", "btp.handshake.client_window_size",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_selected_version,
            {
                "Selected BTP protocol version", "btp.handshake.selected_version",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_selected_segment_size,
            {
                "Selected segment size", "btp.handshake.selected_segment_size",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_btp_selected_window_size,
            {
                "Selected window size", "btp.handshake.selected_window_size",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },

        /* Reassembly fields */
        {
            &hf_btp_fragments,
            {
                "WPAN fragments", "btp.data.fragments",
                FT_NONE, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_fragment,
            {
                "WPAN fragment", "btp.data.fragment",
                FT_FRAMENUM, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_fragment_overlap,
            {
                "WPAN fragment overlap", "btp.data.fragment.overlap",
                FT_BOOLEAN, 0,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_fragment_overlap_conflicts,
            {
                "Message fragment overlapping with conflicting data",
                "btp.data.fragment.overlap.conflicts",
                FT_BOOLEAN, 0,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_fragment_multiple_tails,
            {
                "Message has multiple tail fragments",
                "btp.data.fragment.multiple_tails",
                FT_BOOLEAN, 0,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_fragment_too_long_fragment,
            {
                "Message fragment too long", "btp.data.fragment.too_long_fragment",
                FT_BOOLEAN, 0,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_fragment_error,
            {
                "Message defragmentation error", "btp.data.fragment.error",
                FT_FRAMENUM, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_fragment_count,
            {
                "Message fragment count", "btp.data.fragment.count",
                FT_UINT32, BASE_DEC,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_reassembled_in,
            {
                "Reassembled in", "btp.data.reassembled.in",
                FT_FRAMENUM, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_reassembled_length,
            {
                "Reassembled length", "btp.data.reassembled.length",
                FT_UINT32, BASE_DEC,
                NULL, 0x00,
                NULL, HFILL
            }
        },
        {
            &hf_btp_reassembled_data,
            { "Reassembled data", "btp.data.reassembled.data",
                FT_BYTES, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL
            }
        },

        /* Request/response tracking fields */
        {
            &hf_btp_response_in,
            {
                "Response In", "btp.response_in",
                FT_FRAMENUM, BASE_NONE,
                FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
                "The response to this BTP request is in this frame", HFILL
            }
        },
        {
            &hf_btp_response_to,
            {
                "Request In", "btp.response_to",
                FT_FRAMENUM, BASE_NONE,
                FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
                "This is a response to the BTP request in this frame", HFILL
            }
        },
        {
            &hf_btp_response_time,
            {
                "Response Time", "btp.response_time",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                "The time between the Call and the Reply", HFILL
            }
        },

        /* Acknowledgement tracking fields */
        /* FT_FRAMENUM_[DUP]_ACK causes protocols on top of BTP to have improper ACK display. */
        /* Perhaps consider FT_FRAMENUM_NONE*/
        {
            &hf_btp_acked_by,
            {
                "Acknowledged by", "btp.acknowledged_by",
                FT_FRAMENUM, BASE_NONE,
                FRAMENUM_TYPE(FT_FRAMENUM_DUP_ACK), 0x0,
                "This segment was acknowledged by this frame", HFILL
            }
        },
        {
            &hf_btp_acks_tree,
            {
                "Frames acknowledged by this ACK:", "btp.acknowledge_list",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "This frame acknowledges the following packets", HFILL
            }
        },
        {
            &hf_btp_ack,
            {
                "Frame", "btp.acknowledge_list.value",
                FT_FRAMENUM, BASE_NONE,
                FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0,
                "Frame ID acknowledged by this ACK", HFILL
            }
        },
        {
            &hf_btp_ack_time,
            {
                "Acknowledged in", "btp.acknowledged_time",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                "Time it took to acknowledge this frame", HFILL
            }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btp,
        &ett_btp_version,
        &ett_btp_fragment,
        &ett_btp_fragments,
        &ett_btp_acknowledgements,
        &ett_btp_header
    };

    static ei_register_info ei[] =
    {
        /* Warning info */
        {
            &ei_btp_data_length_invalid,
            {
                "btp.data.length.invalid",
                PI_PROTOCOL, PI_WARN,
                "Reassembled length does not match with length in beginning frame.",
                EXPFILL
            }
        },
        {
            &ei_btp_ack_timeout,
            {
                "btp.acknowledged_by.timeout",
                PI_PROTOCOL, PI_WARN,
                "Frame acknowledgement timed out.",
                EXPFILL
            }
        },
        {
            &ei_btp_handshake_timeout,
            {
                "btp.handshake.timed_out",
                PI_PROTOCOL, PI_WARN,
                "Handshake request timed out.",
                EXPFILL
            }
        },
        {
            &ei_btp_handshake_unknown_error,
            {
                "btp.handshake.unknown_error",
                PI_PROTOCOL, PI_WARN,
                "Unknown protocol error.",
                EXPFILL
            }
        },
        {
            &ei_btp_handshake_request_missing,
            {
                "btp.handshake.request_missing",
                PI_PROTOCOL, PI_WARN,
                "Handshake request is missing",
                EXPFILL
            }
        },
        {
            &ei_btp_data_message_empty,
            {
                "btp.data.length.empty",
                PI_PROTOCOL, PI_WARN,
                "Message is empty",
                EXPFILL
            }
        },

        /* Regular workflow info */
        {
            &ei_btp_keep_alive,
            {
                "btp.keep_alive",
                PI_PROTOCOL, PI_CHAT,
                "This is a keep alive frame.",
                EXPFILL
            }
        }
    };

    /* Register the protocol name and description */
    proto_btp = proto_register_protocol("Bluetooth Transport Protocol", "BTP", "btp");

    /* Register protocol fields */
    proto_register_field_array(proto_btp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register reassembly table for payload */
    reassembly_table_register(&btp_reassembly_table,
        &addresses_reassembly_table_functions);

    /* Register expert info fields */
    expert_btp = expert_register_protocol(proto_btp);
    expert_register_field_array(expert_btp, ei, array_length(ei));
}

/* Name
 *       proto_reg_handoff_btp
 *
 *  Parameters:
 *      None
 *
 *  Return value:
 *      None
 *
 *  Purpose:
 *      Register BTP dissector handle and hook it to underlying protocol
 */
void
proto_reg_handoff_btp(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t btp_handle;

    if (!initialized) {
        /* Use create_dissector_handle() to indicate that
        * dissect_btp() returns the number of bytes it dissected (or 0
        * if it thinks the packet does not belong to BTP).
        */
        btp_handle = create_dissector_handle(dissect_btp, proto_btp);

        /* Attach to UUIDs. Case sensitive. */
        dissector_add_string("bluetooth.uuid", "18ee2ef5-263d-4559-959f-4f9c429f9d11", btp_handle);
        dissector_add_string("bluetooth.uuid", "18ee2ef5-263d-4559-959f-4f9c429f9d12", btp_handle);

        /* Find WPAN dissector handle. */
        wpan_dissector_handle = find_dissector("wpan_nofcs");

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
