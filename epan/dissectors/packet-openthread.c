/* packet-openthread.c
 * Simple dissector for OpenThread loopback interface
 *
 * Robert Cragie <robert.cragie@arm.com>
 *
 * $Id: packet-openthread.c $
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

#include "config.h"

#include <glib.h>
#include <stdlib.h>
#include <epan/packet.h>

/* Forward declarations */
void proto_register_openthread(void);
void proto_reg_handoff_openthread(void);

static int proto_openthread = -1;

static dissector_handle_t openthread_handle;
static dissector_handle_t wpan_handle;

static int hf_openthread_channel = -1;
static int hf_openthread_psdu = -1;

static gint ett_openthread = -1;

static int
dissect_openthread(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *volatile proto_root = NULL;
    proto_tree  *volatile openthread_tree = NULL;
    tvbuff_t    *sub_tvb;
   
    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_openthread, tvb, 0, tvb_reported_length(tvb), "OpenThread");
        openthread_tree = proto_item_add_subtree(proto_root, ett_openthread);
    }

    proto_tree_add_item(openthread_tree, hf_openthread_channel, tvb, 0, 1, FALSE);
    sub_tvb = tvb_new_subset_length(tvb, 1, tvb_reported_length(tvb) - 3); /* Note - truncate the last two "phoney" CRC bytes */
    call_dissector(wpan_handle, sub_tvb, pinfo, openthread_tree);

    return tvb_captured_length(tvb);
}

void
proto_register_openthread(void)
{
  static hf_register_info hf[] = {
    
    /* Generic TLV */
    { &hf_openthread_channel,
      { "Channel",
        "openthread.channel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Channel",
        HFILL
      }
    },
    { &hf_openthread_psdu,
      { "PSDU",
        "openthread.psdu",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "PSDU",
        HFILL
      }
    }
  };
  
  static gint *ett[] = {
    &ett_openthread
  };
  
  proto_openthread = proto_register_protocol("OpenThread", "OpenThread", "openthread");
  proto_register_field_array(proto_openthread, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));  
  register_dissector("openthread", dissect_openthread, proto_openthread);
}

void
proto_reg_handoff_openthread(void)
{
  static gboolean openthread_initialized = FALSE;

  if (!openthread_initialized) {
    openthread_handle = find_dissector("openthread");
    wpan_handle = find_dissector("wpan_nofcs");
    openthread_initialized = TRUE;
  }
  dissector_add_for_decode_as("udp.port", openthread_handle);
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
