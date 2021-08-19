#!/usr/bin/env python2
from __future__ import print_function
import base64
import sys

import openpgp

fname = sys.argv[1]
packets = openpgp.OpenPGPFile(open(fname))
for packet in packets:
    if packet["tag_name"] == "User Attribute":
        for subpacket in packet["subpackets"]:
            image = subpacket["image"]
            with open((fname + "-%d.jpg") % packet["packet_start"], 'wb') as f:
                f.write(base64.b64decode(image))
