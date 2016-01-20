/* packet-coap.c
 * Routines for CoAP packet disassembly
 * draft-ietf-core-coap-14.txt
 * draft-ietf-core-block-10.txt
 * draft-ietf-core-observe-16.txt
 * draft-ietf-core-link-format-06.txt
 * Shoichi Sakane <sakane@tanu.org>
 *
 * Changes for draft-ietf-core-coap-17.txt
 * Hauke Mehrtens <hauke@hauke-m.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-coap.h"

void proto_register_coap(void);

static dissector_table_t media_type_dissector_table;

static int proto_coap = -1;

static int hf_coap_version		= -1;
static int hf_coap_ttype		= -1;
static int hf_coap_token_len		= -1;
static int hf_coap_token		= -1;
static int hf_coap_code			= -1;
static int hf_coap_mid			= -1;
static int hf_coap_payload		= -1;
static int hf_coap_payload_desc		= -1;
static int hf_coap_opt_name		= -1;
static int hf_coap_opt_desc		= -1;
static int hf_coap_opt_delta		= -1;
static int hf_coap_opt_delta_ext	= -1;
static int hf_coap_opt_length		= -1;
static int hf_coap_opt_length_ext	= -1;
static int hf_coap_opt_end_marker	= -1;
static int hf_coap_opt_ctype		= -1;
static int hf_coap_opt_max_age		= -1;
static int hf_coap_opt_proxy_uri	= -1;
static int hf_coap_opt_proxy_scheme	= -1;
static int hf_coap_opt_size1		= -1;
static int hf_coap_opt_etag		= -1;
static int hf_coap_opt_uri_host 	= -1;
static int hf_coap_opt_location_path	= -1;
static int hf_coap_opt_uri_port		= -1;
static int hf_coap_opt_location_query	= -1;
static int hf_coap_opt_uri_path		= -1;
static int hf_coap_opt_uri_path_recon	= -1;
static int hf_coap_opt_observe		= -1;
static int hf_coap_opt_accept		= -1;
static int hf_coap_opt_if_match		= -1;
static int hf_coap_opt_block_number	= -1;
static int hf_coap_opt_block_mflag	= -1;
static int hf_coap_opt_block_size	= -1;
static int hf_coap_opt_uri_query	= -1;
static int hf_coap_opt_unknown		= -1;

static gint ett_coap			= -1;
static gint ett_coap_option		= -1;
static gint ett_coap_payload		= -1;

static expert_field ei_coap_invalid_option_number = EI_INIT;
static expert_field ei_coap_invalid_option_range  = EI_INIT;
static expert_field ei_coap_option_length_bad	  = EI_INIT;

#define MAX_COAP_PORTS 4

/* CoAP's IANA-assigned port number */
#define DEFAULT_COAP_PORT	5683

/* indicators whether those are to be showed or not */
#define DEFAULT_COAP_CTYPE_VALUE	~0U
#define DEFAULT_COAP_BLOCK_NUMBER	~0U

static guint global_coap_port_number[MAX_COAP_PORTS] = { DEFAULT_COAP_PORT };

/*
 * Transaction Type
 */
static const value_string vals_ttype[] = {
	{ 0, "Confirmable" },
	{ 1, "Non-Confirmable" },
	{ 2, "Acknowledgement" },
	{ 3, "Reset" },
	{ 0, NULL },
};
static const value_string vals_ttype_short[] = {
	{ 0, "CON" },
	{ 1, "NON" },
	{ 2, "ACK" },
	{ 3, "RST" },
	{ 0, NULL },
};

/*
 * Method Code
 * Response Code
 */
static const value_string vals_code[] = {
	{ 0, "Empty Message" },

	/* method code */
	{ 1, "GET" },
	{ 2, "POST" },
	{ 3, "PUT" },
	{ 4, "DELETE" },

	/* response code */
	{  65, "2.01 Created" },
	{  66, "2.02 Deleted" },
	{  67, "2.03 Valid" },
	{  68, "2.04 Changed" },
	{  69, "2.05 Content" },
	{ 128, "4.00 Bad Request" },
	{ 129, "4.01 Unauthorized" },
	{ 130, "4.02 Bad Option" },
	{ 131, "4.03 Forbidden" },
	{ 132, "4.04 Not Found" },
	{ 133, "4.05 Method Not Allowed" },
	{ 134, "4.06 Not Acceptable" },
	{ 136, "4.08 Request Entity Incomplete" },	/* core-block-10 */
	{ 140, "4.12 Precondition Failed" },
	{ 141, "4.13 Request Entity Too Large" },
	{ 143, "4.15 Unsupported Content-Format" },
	{ 160, "5.00 Internal Server Error" },
	{ 161, "5.01 Not Implemented" },
	{ 162, "5.02 Bad Gateway" },
	{ 163, "5.03 Service Unavailable" },
	{ 164, "5.04 Gateway Timeout" },
	{ 165, "5.05 Proxying Not Supported" },

	{ 0, NULL },
};
static value_string_ext vals_code_ext = VALUE_STRING_EXT_INIT(vals_code);

static const value_string vals_observe_options[] = {
	{ 0, "Register" },
	{ 1, "Deregister" },
	{ 0, NULL },
};

/*
 * Option Headers
 * No-Option must not be included in this structure, is handled in the function
 * of the dissector, especially.
 */
#define COAP_OPT_IF_MATCH	 1
#define COAP_OPT_URI_HOST	 3
#define COAP_OPT_ETAG		 4
#define COAP_OPT_IF_NONE_MATCH	 5
#define COAP_OPT_OBSERVE	 6	/* core-observe-16 */
#define COAP_OPT_URI_PORT	 7
#define COAP_OPT_LOCATION_PATH	 8
#define COAP_OPT_URI_PATH	11
#define COAP_OPT_CONTENT_TYPE	12
#define COAP_OPT_MAX_AGE	14
#define COAP_OPT_URI_QUERY	15
#define COAP_OPT_ACCEPT		17
#define COAP_OPT_LOCATION_QUERY	20
#define COAP_OPT_BLOCK2		23	/* core-block-10 */
#define COAP_OPT_BLOCK_SIZE	28	/* core-block-10 */
#define COAP_OPT_BLOCK1		27	/* core-block-10 */
#define COAP_OPT_PROXY_URI	35
#define COAP_OPT_PROXY_SCHEME	39
#define COAP_OPT_SIZE1		60

static const value_string vals_opt_type[] = {
	{ COAP_OPT_IF_MATCH,       "If-Match" },
	{ COAP_OPT_URI_HOST,       "Uri-Host" },
	{ COAP_OPT_ETAG,           "Etag" },
	{ COAP_OPT_IF_NONE_MATCH,  "If-None-Match" },
	{ COAP_OPT_URI_PORT,       "Uri-Port" },
	{ COAP_OPT_LOCATION_PATH,  "Location-Path" },
	{ COAP_OPT_URI_PATH,       "Uri-Path" },
	{ COAP_OPT_CONTENT_TYPE,   "Content-Format" },
	{ COAP_OPT_MAX_AGE,        "Max-age" },
	{ COAP_OPT_URI_QUERY,      "Uri-Query" },
	{ COAP_OPT_ACCEPT,         "Accept" },
	{ COAP_OPT_LOCATION_QUERY, "Location-Query" },
	{ COAP_OPT_PROXY_URI,      "Proxy-Uri" },
	{ COAP_OPT_PROXY_SCHEME,   "Proxy-Scheme" },
	{ COAP_OPT_SIZE1,          "Size1" },
	{ COAP_OPT_OBSERVE,        "Observe" },
	{ COAP_OPT_BLOCK2,         "Block2" },
	{ COAP_OPT_BLOCK1,         "Block1" },
	{ COAP_OPT_BLOCK_SIZE,     "Block Size" },
	{ 0, NULL },
};

struct coap_option_range_t {
	guint type;
	gint min;
	gint max;
} coi[] = {
	{ COAP_OPT_IF_MATCH,       0,   8 },
	{ COAP_OPT_URI_HOST,       1, 255 },
	{ COAP_OPT_ETAG,           1,   8 },
	{ COAP_OPT_IF_NONE_MATCH,  0,   0 },
	{ COAP_OPT_URI_PORT,       0,   2 },
	{ COAP_OPT_LOCATION_PATH,  0, 255 },
	{ COAP_OPT_URI_PATH,       0, 255 },
	{ COAP_OPT_CONTENT_TYPE,   0,   2 },
	{ COAP_OPT_MAX_AGE,        0,   4 },
	{ COAP_OPT_URI_QUERY,      1, 255 },
	{ COAP_OPT_ACCEPT,         0,   2 },
	{ COAP_OPT_LOCATION_QUERY, 0, 255 },
	{ COAP_OPT_PROXY_URI,      1,1034 },
	{ COAP_OPT_PROXY_SCHEME,   1, 255 },
	{ COAP_OPT_SIZE1,          0,   4 },
	{ COAP_OPT_OBSERVE,        0,   3 },
	{ COAP_OPT_BLOCK2,         0,   3 },
	{ COAP_OPT_BLOCK1,         0,   3 },
	{ COAP_OPT_BLOCK_SIZE,     0,   4 },
};

static const value_string vals_ctype[] = {
	{  0, "text/plain; charset=utf-8" },
	{ 40, "application/link-format" },
	{ 41, "application/xml" },
	{ 42, "application/octet-stream" },
	{ 47, "application/exi" },
	{ 50, "application/json" },
	{ 60, "application/cbor" },
	{ 0, NULL },
};

static const char *nullstr = "(null)";

void proto_reg_handoff_coap(void);

static conversation_t *
find_or_create_conversation_noaddrb(packet_info *pinfo)
{
	conversation_t *conv=NULL;

	/* Have we seen this conversation before? */
	if((conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				     pinfo->ptype, pinfo->srcport,
				     pinfo->destport, NO_ADDR_B|NO_PORT_B)) != NULL) {
		if (pinfo->fd->num > conv->last_frame) {
			conv->last_frame = pinfo->fd->num;
		}
	} else {
		/* No, this is a new conversation. */
		conv = conversation_new(pinfo->fd->num, &pinfo->src,
					&pinfo->dst, pinfo->ptype,
					pinfo->srcport, pinfo->destport, NO_ADDR_B|NO_PORT_B);
	}
	return conv;
}

static gint
coap_get_opt_uint(tvbuff_t *tvb, gint offset, gint length)
{
	switch (length) {
	case 0:
		return 0;
	case 1:
		return (guint)tvb_get_guint8(tvb, offset);
	case 2:
		return (guint)tvb_get_ntohs(tvb, offset);
	case 3:
		return (guint)tvb_get_ntoh24(tvb, offset);
	case 4:
		return (guint)tvb_get_ntohl(tvb, offset);
	default:
		return -1;
	}
}

static gint
coap_opt_check(packet_info *pinfo, proto_tree *subtree, guint opt_num, gint opt_length)
{
	int i;

	for (i = 0; i < (int)(array_length(coi)); i++) {
		if (coi[i].type == opt_num)
			break;
	}
	if (i == (int)(array_length(coi))) {
		expert_add_info_format(pinfo, subtree, &ei_coap_invalid_option_number,
			"Invalid Option Number %u", opt_num);
		return -1;
	}
	if (opt_length < coi[i].min || opt_length > coi[i].max) {
		expert_add_info_format(pinfo, subtree, &ei_coap_invalid_option_range,
			"Invalid Option Range: %d (%d < x < %d)", opt_length, coi[i].min, coi[i].max);
	}

	return 0;
}

static void
dissect_coap_opt_hex_string(tvbuff_t *tvb, proto_item *item, proto_tree *subtree, gint offset, gint opt_length, int hf)
{
	const guint8 *str;

	if (opt_length == 0)
		str = nullstr;
	else
		str = tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, offset, opt_length, ' ');

	proto_tree_add_item(subtree, hf, tvb, offset, opt_length, ENC_NA);

	/* add info to the head of the packet detail */
	proto_item_append_text(item, ": %s", str);
}

static void
dissect_coap_opt_uint(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, int hf)
{
	guint i = 0;

	if (opt_length != 0) {
		i = coap_get_opt_uint(tvb, offset, opt_length);
	}

	proto_tree_add_uint(subtree, hf, tvb, offset, opt_length, i);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %u", i);
}

static void
dissect_coap_opt_uri_host(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo)
{
	guint8 *str;

	str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, opt_length, ENC_ASCII);

	proto_tree_add_string(subtree, hf_coap_opt_uri_host, tvb, offset, opt_length, str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", str);

	/* forming a uri-string
	 *   If the 'uri host' looks an IPv6 address, assuming that the address has
	 *   to be enclosed by brackets.
	 */
	if (strchr(str, ':') == NULL) {
		wmem_strbuf_append_printf(coinfo->uri_str_strbuf, "coap://%s", str);
	} else {
		wmem_strbuf_append_printf(coinfo->uri_str_strbuf, "coap://[%s]", str);
	}
}

static void
dissect_coap_opt_uri_path(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo)
{
	const guint8 *str = NULL;

	wmem_strbuf_append_c(coinfo->uri_str_strbuf, '/');

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, opt_length, ENC_ASCII);
		wmem_strbuf_append(coinfo->uri_str_strbuf, str);
	}

	proto_tree_add_string(subtree, hf_coap_opt_uri_path, tvb, offset, opt_length, str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", str);
}

static void
dissect_coap_opt_uri_query(tvbuff_t *tvb, proto_item *head_item,proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo)
{
	const guint8 *str = NULL;

	wmem_strbuf_append_c(coinfo->uri_query_strbuf,
			     (wmem_strbuf_get_len(coinfo->uri_query_strbuf) == 0) ? '?' : '&');

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, opt_length, ENC_ASCII);
		wmem_strbuf_append(coinfo->uri_query_strbuf, str);
	}

	proto_tree_add_string(subtree, hf_coap_opt_uri_query, tvb, offset, opt_length, str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", str);
}

static void
dissect_coap_opt_location_path(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length)
{
	const guint8 *str = NULL;

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, opt_length, ENC_ASCII);
	}

	proto_tree_add_string(subtree, hf_coap_opt_location_path, tvb, offset, opt_length, str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", str);
}

static void
dissect_coap_opt_location_query(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length)
{
	const guint8 *str = NULL;

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, opt_length, ENC_ASCII);
	}

	proto_tree_add_string(subtree, hf_coap_opt_location_query, tvb, offset, opt_length, str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", str);
}

static void
dissect_coap_opt_proxy_uri(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length)
{
	const guint8 *str = NULL;

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, opt_length, ENC_ASCII);
	}

	proto_tree_add_string(subtree, hf_coap_opt_proxy_uri, tvb, offset, opt_length, str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", str);
}

static void
dissect_coap_opt_proxy_scheme(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length)
{
	const guint8 *str = NULL;

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, opt_length, ENC_ASCII);
	}

	proto_tree_add_string(subtree, hf_coap_opt_proxy_scheme, tvb, offset, opt_length, str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", str);
}

static void
dissect_coap_opt_ctype(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, int hf, coap_info *coinfo)
{
	if (opt_length == 0) {
		coinfo->ctype_value = 0;
	} else {
		coinfo->ctype_value = coap_get_opt_uint(tvb, offset, opt_length);
	}

	coinfo->ctype_str = val_to_str(coinfo->ctype_value, vals_ctype, "Unknown Type %u");

	proto_tree_add_string(subtree, hf, tvb, offset, opt_length, coinfo->ctype_str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", coinfo->ctype_str);
}

static void
dissect_coap_opt_block(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo)
{
	guint8      val                = 0;
	guint       encoded_block_size;
	guint       block_esize;

	if (opt_length == 0) {
		coinfo->block_number = 0;
		val = 0;
	} else {
		coinfo->block_number = coap_get_opt_uint(tvb, offset, opt_length) >> 4;
		val = tvb_get_guint8(tvb, offset + opt_length - 1) & 0x0f;
	}

	proto_tree_add_uint(subtree, hf_coap_opt_block_number,
	    tvb, offset, opt_length, coinfo->block_number);

	/* More flag in the end of the option */
	coinfo->block_mflag = val & 0x08;
	proto_tree_add_uint(subtree, hf_coap_opt_block_mflag,
	    tvb, offset + opt_length - 1, 1, coinfo->block_mflag);

	/* block size */
	encoded_block_size = val & 0x07;
	block_esize = 1 << (encoded_block_size + 4);
	proto_tree_add_uint_format(subtree, hf_coap_opt_block_size,
	    tvb, offset + opt_length - 1, 1, encoded_block_size, "Block Size: %u (%u encoded)", block_esize, encoded_block_size);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": NUM:%u, M:%u, SZX:%u",
	    coinfo->block_number, coinfo->block_mflag, block_esize);
}

static void
dissect_coap_opt_uri_port(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo)
{
	guint port = 0;

	if (opt_length != 0) {
		port = coap_get_opt_uint(tvb, offset, opt_length);
	}

	proto_tree_add_uint(subtree, hf_coap_opt_uri_port, tvb, offset, opt_length, port);

	proto_item_append_text(head_item, ": %u", port);

	/* forming a uri-string */
	wmem_strbuf_append_printf(coinfo->uri_str_strbuf, ":%u", port);
}

/*
 * dissector for each option of CoAP.
 * return the total length of the option including the header (e.g. delta and length).
 */
static int
dissect_coap_options_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *coap_tree, gint offset, guint8 opt_count, guint *opt_num, gint coap_length, coap_info *coinfo)
{
	guint8      opt_jump;
	gint        opt_length, opt_length_ext, opt_delta, opt_delta_ext;
	gint        opt_length_ext_off = 0;
	gint8       opt_length_ext_len = 0;
	gint        opt_delta_ext_off  = 0;
	gint8       opt_delta_ext_len  = 0;
	gint        orig_offset	       = offset;
	proto_tree *subtree;
	proto_item *item;
	char	    strbuf[56];

	opt_jump = tvb_get_guint8(tvb, offset);
	if (0xff == opt_jump)
		return offset;
	offset += 1;

	/*
	 * section 3.1 in coap-17:
	 * Option Delta:  4-bit unsigned integer.  A value between 0 and 12
	 * indicates the Option Delta.  Three values are reserved for special
	 * constructs:
	 *
	 * 13:  An 8-bit unsigned integer follows the initial byte and
	 *      indicates the Option Delta minus 13.
	 *
	 * 14:  A 16-bit unsigned integer in network byte order follows the
	 *      initial byte and indicates the Option Delta minus 269.
	 *
	 * 15:  Reserved for the Payload Marker.  If the field is set to this
	 *      value but the entire byte is not the payload marker, this MUST
	 *      be processed as a message format error.
	 */
	switch (opt_jump & 0xf0) {
	case 0xd0:
		opt_delta_ext = tvb_get_guint8(tvb, offset);
		opt_delta_ext_off = offset;
		opt_delta_ext_len = 1;
		offset += 1;

		opt_delta = 13;
		opt_delta += opt_delta_ext;
		break;
	case 0xe0:
		opt_delta_ext = coap_get_opt_uint(tvb, offset, 2);
		opt_delta_ext_off = offset;
		opt_delta_ext_len = 2;
		offset += 2;

		opt_delta = 269;
		opt_delta += opt_delta_ext;
		break;
	case 0xf0:
		expert_add_info_format(pinfo, coap_tree, &ei_coap_option_length_bad,
				"end-of-options marker found, but option length isn't 15");
		return -1;
	default:
		opt_delta = ((opt_jump & 0xf0) >> 4);
		break;
	}
	*opt_num += opt_delta;

	/*
	 * section 3.1 in coap-17:
	 * Option Length:  4-bit unsigned integer.  A value between 0 and 12
	 * indicates the length of the Option Value, in bytes.  Three values
	 * are reserved for special constructs:
	 *
	 * 13:  An 8-bit unsigned integer precedes the Option Value and
	 *      indicates the Option Length minus 13.
	 *
	 * 14:  A 16-bit unsigned integer in network byte order precedes the
	 *      Option Value and indicates the Option Length minus 269.
	 *
	 * 15:  Reserved for future use.  If the field is set to this value,
	 *      it MUST be processed as a message format error.
	 */
	switch (opt_jump & 0x0f) {
	case 0x0d:
		opt_length_ext = tvb_get_guint8(tvb, offset);
		opt_length_ext_off = offset;
		opt_length_ext_len = 1;
		offset += 1;

		opt_length  = 13;
		opt_length += opt_length_ext;
		break;
	case 0x0e:
		opt_length_ext = coap_get_opt_uint(tvb, offset, 2);
		opt_length_ext_off = offset;
		opt_length_ext_len = 2;
		offset += 2;

		opt_length  = 269;
		opt_length += opt_length_ext;
		break;
	case 0x0f:
		expert_add_info_format(pinfo, coap_tree, &ei_coap_option_length_bad,
			"end-of-options marker found, but option delta isn't 15");
		return -1;
	default:
		opt_length = (opt_jump & 0x0f);
		break;
	}
	if (offset + opt_length > coap_length) {
		expert_add_info_format(pinfo, coap_tree, &ei_coap_option_length_bad,
			"option longer than the package");
		return -1;
	}

	coap_opt_check(pinfo, coap_tree, *opt_num, opt_length);

	g_snprintf(strbuf, sizeof(strbuf),
	    "#%u: %s", opt_count, val_to_str_const(*opt_num, vals_opt_type,
	    *opt_num % 14 == 0 ? "No-Op" : "Unknown Option"));
	item = proto_tree_add_string(coap_tree, hf_coap_opt_name,
	    tvb, orig_offset, offset - orig_offset + opt_length, strbuf);
	subtree = proto_item_add_subtree(item, ett_coap_option);

	g_snprintf(strbuf, sizeof(strbuf),
	    "Type %u, %s, %s%s", *opt_num,
	    (*opt_num & 1) ? "Critical" : "Elective",
	    (*opt_num & 2) ? "Unsafe" : "Safe",
	    ((*opt_num & 0x1e) == 0x1c) ? ", NoCacheKey" : "");
	proto_tree_add_string(subtree, hf_coap_opt_desc,
	    tvb, orig_offset, offset - orig_offset + opt_length, strbuf);

	proto_tree_add_item(subtree, hf_coap_opt_delta,  tvb, orig_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_coap_opt_length, tvb, orig_offset, 1, ENC_BIG_ENDIAN);

	if (opt_delta_ext_off && opt_delta_ext_len)
		proto_tree_add_item(subtree, hf_coap_opt_delta_ext, tvb, opt_delta_ext_off, opt_delta_ext_len, ENC_BIG_ENDIAN);

	if (opt_length_ext_off && opt_length_ext_len)
		proto_tree_add_item(subtree, hf_coap_opt_length_ext, tvb, opt_length_ext_off, opt_length_ext_len, ENC_BIG_ENDIAN);

	/* offset points the next to its option header */
	switch (*opt_num) {
	case COAP_OPT_CONTENT_TYPE:
		dissect_coap_opt_ctype(tvb, item, subtree, offset,
		    opt_length, hf_coap_opt_ctype, coinfo);
		break;
	case COAP_OPT_MAX_AGE:
		dissect_coap_opt_uint(tvb, item, subtree, offset,
		    opt_length, hf_coap_opt_max_age);
		break;
	case COAP_OPT_PROXY_URI:
		dissect_coap_opt_proxy_uri(tvb, item, subtree, offset,
		    opt_length);
		break;
	case COAP_OPT_PROXY_SCHEME:
		dissect_coap_opt_proxy_scheme(tvb, item, subtree, offset,
		    opt_length);
		break;
	case COAP_OPT_SIZE1:
		dissect_coap_opt_uint(tvb, item, subtree, offset,
		    opt_length, hf_coap_opt_size1);
		break;
	case COAP_OPT_ETAG:
		dissect_coap_opt_hex_string(tvb, item, subtree, offset,
		    opt_length, hf_coap_opt_etag);
		break;
	case COAP_OPT_URI_HOST:
		dissect_coap_opt_uri_host(tvb, item, subtree, offset,
		    opt_length, coinfo);
		break;
	case COAP_OPT_LOCATION_PATH:
		dissect_coap_opt_location_path(tvb, item, subtree, offset,
		    opt_length);
		break;
	case COAP_OPT_URI_PORT:
		dissect_coap_opt_uri_port(tvb, item, subtree, offset,
		    opt_length, coinfo);
		break;
	case COAP_OPT_LOCATION_QUERY:
		dissect_coap_opt_location_query(tvb, item, subtree, offset,
		    opt_length);
		break;
	case COAP_OPT_URI_PATH:
		dissect_coap_opt_uri_path(tvb, item, subtree, offset,
		    opt_length, coinfo);
		break;
	case COAP_OPT_OBSERVE:
		dissect_coap_opt_uint(tvb, item, subtree, offset,
		    opt_length, hf_coap_opt_observe);
		break;
	case COAP_OPT_ACCEPT:
		dissect_coap_opt_ctype(tvb, item, subtree, offset,
		    opt_length, hf_coap_opt_accept, coinfo);
		break;
	case COAP_OPT_IF_MATCH:
		dissect_coap_opt_hex_string(tvb, item, subtree, offset,
		    opt_length, hf_coap_opt_if_match);
		break;
	case COAP_OPT_URI_QUERY:
		dissect_coap_opt_uri_query(tvb, item, subtree, offset,
		    opt_length, coinfo);
		break;
	case COAP_OPT_BLOCK2:
		dissect_coap_opt_block(tvb, item, subtree, offset,
		    opt_length, coinfo);
		break;
	case COAP_OPT_BLOCK1:
		dissect_coap_opt_block(tvb, item, subtree, offset,
		    opt_length, coinfo);
		break;
	case COAP_OPT_IF_NONE_MATCH:
		break;
	case COAP_OPT_BLOCK_SIZE:
		dissect_coap_opt_uint(tvb, item, subtree, offset,
		    opt_length, hf_coap_opt_block_size);
		break;
	default:
		dissect_coap_opt_hex_string(tvb, item, subtree, offset,
		    opt_length, hf_coap_opt_unknown);
		break;
	}

	return offset + opt_length;
}

/*
 * options dissector.
 * return offset pointing the next of options. (i.e. the top of the paylaod
 * or the end of the data.
 */
static int
dissect_coap_options(tvbuff_t *tvb, packet_info *pinfo, proto_tree *coap_tree, gint offset, gint coap_length, coap_info *coinfo)
{
	guint  opt_num = 0;
	int    i;
	guint8 endmarker;

	/* loop for dissecting options */
	for (i = 1; offset < coap_length; i++) {
		offset = dissect_coap_options_main(tvb, pinfo, coap_tree,
		    offset, i, &opt_num, coap_length, coinfo);
		if (offset == -1)
			return -1;
		if (offset >= coap_length)
			break;
		endmarker = tvb_get_guint8(tvb, offset);
		if (endmarker == 0xff) {
			proto_tree_add_item(coap_tree, hf_coap_opt_end_marker, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		}
	}

	return offset;
}

static void
dissect_coap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	gint              offset = 0;
	proto_item       *coap_root;
	proto_item       *pi;
	proto_tree       *coap_tree;
	guint8            ttype;
	guint8            token_len;
	guint8            code;
	guint8            code_class;
	guint16           mid;
	gint              coap_length;
	gchar            *coap_token_str;
	coap_info        *coinfo;
    conversation_t   *conversation;
    coap_conv_info   *ccinfo;
    coap_transaction *coap_trans;

	/* Allocate information for upper layers */
	if (!PINFO_FD_VISITED(pinfo)) {
		coinfo = wmem_new0(wmem_file_scope(), coap_info);
		p_add_proto_data(wmem_file_scope(), pinfo, proto_coap, 0, coinfo);
	} else {
		coinfo = (coap_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_coap, 0);
	}

	/* initialize the CoAP length and the content-Format */
	/*
	 * the length of CoAP message is not specified in the CoAP header.
	 * It has to be from the lower layer.
	 * Currently, the length is just copied from the reported length of the tvbuffer.
	 */
	coap_length = tvb_reported_length(tvb);
    coinfo->ctype_str = "";
    coinfo->ctype_value = DEFAULT_COAP_CTYPE_VALUE;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoAP");
	col_clear(pinfo->cinfo, COL_INFO);

	coap_root = proto_tree_add_item(parent_tree, proto_coap, tvb, offset, -1, ENC_NA);
	coap_tree = proto_item_add_subtree(coap_root, ett_coap);

	proto_tree_add_item(coap_tree, hf_coap_version, tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(coap_tree, hf_coap_ttype, tvb, offset, 1, ENC_BIG_ENDIAN);
	ttype = (tvb_get_guint8(tvb, offset) & 0x30) >> 4;

	proto_tree_add_item(coap_tree, hf_coap_token_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	token_len = tvb_get_guint8(tvb, offset) & 0x0f;

	offset += 1;

	proto_tree_add_item(coap_tree, hf_coap_code, tvb, offset, 1, ENC_BIG_ENDIAN);
	code = tvb_get_guint8(tvb, offset);
	offset += 1;

	proto_tree_add_item(coap_tree, hf_coap_mid, tvb, offset, 2, ENC_BIG_ENDIAN);
	mid = tvb_get_ntohs(tvb, offset);

	col_add_fstr(pinfo->cinfo, COL_INFO,
		     "%s, MID:%u, %s",
		     val_to_str(ttype, vals_ttype_short, "Unknown %u"),
		     mid,
		     val_to_str_ext(code, &vals_code_ext, "Unknown %u"));

	/* append the header information */
	proto_item_append_text(coap_root,
			       ", %s, MID:%u, %s",
			       val_to_str(ttype, vals_ttype, "Unknown %u"),
			       mid,
			       val_to_str_ext(code, &vals_code_ext, "Unknown %u"));

	offset += 2;

	/* initialize the external value */
    coinfo->block_number = DEFAULT_COAP_BLOCK_NUMBER;
    coinfo->block_mflag  = 0;
    coinfo->uri_str_strbuf   = wmem_strbuf_sized_new(wmem_packet_scope(), 0, 1024);
    coinfo->uri_query_strbuf = wmem_strbuf_sized_new(wmem_packet_scope(), 0, 1024);
    
	coap_token_str = NULL;
	if (token_len > 0) {
		//coap_token_str = tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, offset, token_len, ' ');
		coap_token_str = tvb_bytes_to_str_punct(wmem_file_scope(), tvb, offset, token_len, ' ');
		proto_tree_add_item(coap_tree, hf_coap_token,
				    tvb, offset, token_len, ENC_NA);
		offset += token_len;
	}

	/* process options */
	offset = dissect_coap_options(tvb, pinfo, coap_tree, offset, coap_length, coinfo);
	if (offset == -1)
		return;

    /* Use conversations to track state for request/response */
    conversation = find_or_create_conversation_noaddrb(pinfo);

    /* Retrieve or create state structure for this conversation */
    ccinfo = (coap_conv_info *)conversation_get_proto_data(conversation, proto_coap);
    if (!ccinfo) {
        /* No state structure - create it */
        ccinfo = wmem_new(wmem_file_scope(), coap_conv_info);
        ccinfo->messages = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        conversation_add_proto_data(conversation, proto_coap, ccinfo);
    }

    /* Everything based on tokens */
    if (coap_token_str) {
        /* Process request/response in conversation */
        if (code == 1) {
            int i;
            /* Trap for breakpoint - looking for GET */
            i = 0xFEED;
        }
        if (code != 0) { /* Ignore empty messages */
            /* Try and look up a matching token. If it's the first
             * sight of a request, there shouldn't be one */
            code_class = code >> 5;
            coap_trans = (coap_transaction *)wmem_map_lookup(ccinfo->messages, coap_token_str);
            if (!coap_trans) {
                if ((!PINFO_FD_VISITED(pinfo)) && (code_class == 0)) {
                    /* New request - log it */
                    coap_trans = wmem_new(wmem_file_scope(), coap_transaction);
                    coap_trans->req_frame = PINFO_FD_NUM(pinfo);
                    coap_trans->rsp_frame = 0;
                    if (coinfo->uri_str_strbuf) {
                        /* Store the URI into CoAP transaction info */
                        coap_trans->uri_str_strbuf = wmem_strbuf_new(wmem_file_scope(), wmem_strbuf_get_str(coinfo->uri_str_strbuf));
                    }
                    wmem_map_insert(ccinfo->messages, coap_token_str, (void *)coap_trans);
                }
            } else {
                if ((code_class >= 2) && (code_class <= 5)) {
                    if (!PINFO_FD_VISITED(pinfo)) {
                        /* Log the first matching response frame */
                        coap_trans->rsp_frame = PINFO_FD_NUM(pinfo);
                    }
                    if (coap_trans->uri_str_strbuf) {
                        /* Copy the URI stored in matching transaction info into CoAP packet info */
                        coinfo->uri_str_strbuf = wmem_strbuf_new(wmem_packet_scope(), wmem_strbuf_get_str(coap_trans->uri_str_strbuf));
                    }
                }
            }
        }
    }
    
 	/* add informations to the packet list */
	if (coap_token_str != NULL)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", TKN:%s", coap_token_str);
	if (coinfo->block_number != DEFAULT_COAP_BLOCK_NUMBER)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %sBlock #%u",
				coinfo->block_mflag ? "" : "End of ", coinfo->block_number);
	if (wmem_strbuf_get_len(coinfo->uri_str_strbuf) > 0) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", wmem_strbuf_get_str(coinfo->uri_str_strbuf));
        pi = proto_tree_add_string(coap_tree, hf_coap_opt_uri_path_recon, tvb, 0, 0, wmem_strbuf_get_str(coinfo->uri_str_strbuf));
        PROTO_ITEM_SET_HIDDEN(pi);
    }
	if (wmem_strbuf_get_len(coinfo->uri_query_strbuf)> 0)
		col_append_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(coinfo->uri_query_strbuf));

	/* dissect the payload */
	if (coap_length > offset) {
		proto_tree *payload_tree;
		proto_item *payload_item;
		tvbuff_t   *payload_tvb;
		guint	    payload_length = coap_length - offset;
		const char *coap_ctype_str_dis;
		char	    str_payload[80];

		/*
		 * 5.5.2.  Diagnostic Payload
		 *
		 * If no Content-Format option is given, the payload of responses
		 * indicating a client or server error is a brief human-readable
		 * diagnostic message, explaining the error situation. This diagnostic
		 * message MUST be encoded using UTF-8 [RFC3629], more specifically
		 * using Net-Unicode form [RFC5198].
		 */
		if (coinfo->ctype_value == DEFAULT_COAP_CTYPE_VALUE)
			coinfo->ctype_str = "text/plain; charset=utf-8";

		g_snprintf(str_payload, sizeof(str_payload),
		    "Payload Content-Format: %s%s, Length: %u",
		    coinfo->ctype_str, coinfo->ctype_value == DEFAULT_COAP_CTYPE_VALUE ?
		    " (no Content-Format)" : "", payload_length);

		payload_item = proto_tree_add_string(coap_tree, hf_coap_payload,
						     tvb, offset, payload_length,
						     str_payload);
		payload_tree = proto_item_add_subtree(payload_item, ett_coap_payload);

		proto_tree_add_string(payload_tree, hf_coap_payload_desc, tvb, offset, -1, coinfo->ctype_str);
		payload_tvb = tvb_new_subset_length(tvb, offset, payload_length);

		if (coinfo->ctype_value == DEFAULT_COAP_CTYPE_VALUE || coinfo->ctype_value == 0) {
			coap_ctype_str_dis = "text/plain";
		} else {
			coap_ctype_str_dis = coinfo->ctype_str;
		}

		dissector_try_string(media_type_dissector_table, coap_ctype_str_dis,
				     payload_tvb, pinfo, payload_tree, NULL);
	}
}

/*
 * Protocol initialization
 */
void
proto_register_coap(void)
{
	static hf_register_info hf[] = {
		{ &hf_coap_version,
		  { "Version", "coap.version",
		    FT_UINT8, BASE_DEC, NULL, 0xc0,
		    NULL, HFILL }
		},
		{ &hf_coap_ttype,
		  { "Type", "coap.type",
		    FT_UINT8, BASE_DEC, VALS(vals_ttype), 0x30,
		    NULL, HFILL }
		},
		{ &hf_coap_token_len,
		  { "Token Length", "coap.token_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0f,
		    NULL, HFILL }
		},
		{ &hf_coap_token,
		  { "Token", "coap.token",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_code,
		  { "Code", "coap.code",
		    FT_UINT8, BASE_DEC | BASE_EXT_STRING, &vals_code_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_mid,
		  { "Message ID", "coap.mid",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_payload,
		  { "Payload", "coap.payload",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_payload_desc,
		  { "Payload Desc", "coap.opt.payload_desc",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_name,
		  { "Opt Name", "coap.opt.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_desc,
		  { "Opt Desc", "coap.opt.desc",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_delta,
		  { "Opt Delta", "coap.opt.delta",
		    FT_UINT8, BASE_DEC, NULL, 0xf0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_delta_ext,
		  { "Opt Delta extended", "coap.opt.delta_ext",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_length,
		  { "Opt Length", "coap.opt.length",
		    FT_UINT8, BASE_DEC, NULL, 0x0f,
		    "CoAP Option Length", HFILL }
		},
		{ &hf_coap_opt_length_ext,
		  { "Opt Length extended", "coap.opt.length_ext",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_end_marker,
		  { "End of options marker", "coap.opt.end_marker",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_ctype,
		  { "Content-type", "coap.opt.ctype",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_max_age,
		  { "Max-age", "coap.opt.max_age",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_proxy_uri,
		  { "Proxy-Uri", "coap.opt.proxy_uri",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_proxy_scheme,
		  { "Proxy-Scheme", "coap.opt.proxy_scheme",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_size1,
		  { "Size1", "coap.opt.size1",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_etag,
		  { "Etag", "coap.opt.etag",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "CoAP Option Etag", HFILL }
		},
		{ &hf_coap_opt_uri_host,
		  { "Uri-Host", "coap.opt.uri_host",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_location_path,
		  { "Location-Path", "coap.opt.location_path",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_uri_port,
		  { "Uri-Port", "coap.opt.uri_port",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_location_query,
		  { "Location-Query", "coap.opt.location_query",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_uri_path,
		  { "Uri-Path", "coap.opt.uri_path",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_uri_path_recon,
		  { "Uri-Path", "coap.opt.uri_path_recon",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_observe,
		  { "Observe", "coap.opt.observe",
		    FT_UINT32, BASE_DEC, VALS(vals_observe_options), 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_accept,
		  { "Accept", "coap.opt.accept",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_if_match,
		  { "If-Match", "coap.opt.if_match",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_block_number,
		  { "Block Number", "coap.opt.block_number",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_block_mflag,
		  { "More Flag", "coap.opt.block_mflag",
		    FT_UINT8, BASE_DEC, NULL, 0x08,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_block_size,
		  { "Encoded Block Size", "coap.opt.block_size",
		    FT_UINT8, BASE_DEC, NULL, 0x07,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_uri_query,
		  { "Uri-Query", "coap.opt.uri_query",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_opt_unknown,
		  { "Unknown", "coap.opt.unknown",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_coap,
		&ett_coap_option,
		&ett_coap_payload,
	};

	static ei_register_info ei[] = {
		{ &ei_coap_invalid_option_number,
		  { "coap.invalid_option_number", PI_MALFORMED, PI_WARN, "Invalid Option Number", EXPFILL }},
		{ &ei_coap_invalid_option_range,
		  { "coap.invalid_option_range", PI_MALFORMED, PI_WARN, "Invalid Option Range", EXPFILL }},
		{ &ei_coap_option_length_bad,
		  { "coap.option_length_bad", PI_MALFORMED, PI_WARN, "Option length bad", EXPFILL }},
	};

	module_t	*coap_module;
	expert_module_t *expert_coap;

	proto_coap = proto_register_protocol("Constrained Application Protocol", "CoAP", "coap");
	proto_register_field_array(proto_coap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_coap = expert_register_protocol(proto_coap);
	expert_register_field_array(expert_coap, ei, array_length(ei));

	register_dissector("coap", dissect_coap, proto_coap);

	/* Register our configuration options */
	coap_module = prefs_register_protocol (proto_coap, proto_reg_handoff_coap);

	prefs_register_uint_preference (coap_module, "udp_port",
					"CoAP port number",
					"Port number used for CoAP traffic",
					10, &global_coap_port_number[0]);
	prefs_register_uint_preference (coap_module, "udp_port_a1",
					"Additional CoAP port number (1)",
					"Additional port number (1) used for CoAP traffic",
					10, &global_coap_port_number[1]);
	prefs_register_uint_preference (coap_module, "udp_port_a2",
					"Additional CoAP port number (2)",
					"Additional port number (2) used for CoAP traffic",
					10, &global_coap_port_number[2]);
	prefs_register_uint_preference (coap_module, "udp_port_a3",
					"Additional CoAP port number (3)",
					"Additional port number (3) used for CoAP traffic",
					10, &global_coap_port_number[3]);
}

void
proto_reg_handoff_coap(void)
{
	static gboolean coap_prefs_initialized = FALSE;
	static dissector_handle_t coap_handle;
	static guint coap_port_number[MAX_COAP_PORTS];
    guint i;

	if (!coap_prefs_initialized) {
		coap_handle = find_dissector("coap");
		media_type_dissector_table = find_dissector_table("media_type");
		coap_prefs_initialized = TRUE;
	} else {
        for (i = 0; i < MAX_COAP_PORTS; i++) {
            dissector_delete_uint("udp.port", coap_port_number[i], coap_handle);
            dissector_delete_uint("tcp.port", coap_port_number[i], coap_handle);
        }
	}

    for (i = 0; i < MAX_COAP_PORTS; i++) {
        coap_port_number[i] = global_coap_port_number[i];
        dissector_add_uint("udp.port", coap_port_number[i], coap_handle);
        dissector_add_uint("tcp.port", coap_port_number[i], coap_handle);
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
