#!/usr/bin/env python

import os
import re
import bz2
import math
import zlib
import base64
import hashlib
import tempfile
import cStringIO

class OpenPGPFile(list):
    """
    A list of parsed packets in an OpenPGP file. I wrote this to have a better
    understanding of the OpenPGP format. It is designed to be very readable,
    use low memory, and use Python's built-in list and dict objects.

    Object format = [
        {
            #standard packet values
            "packet_format": 0 or 1,
            "packet_start": 123,
            "packet_raw": "deadbeefdeadbeefdeadbeef...",
            "tag_id": 2,
            "tag_name": "Signature",
            "body_start": 0,
            "body_len": 423,

            #errors (if any)
            "error": True,
            "error_msg": ["Error msg 1", "Error msg 2"],

            #packet specific keys (see each read_* method for format)
            ...
        },
        ...
    ]
    """
    rawfile = None

    def __init__(self, fileobj_or_list):

        #read the file and load the list
        if hasattr(fileobj_or_list, "read"):
            super(OpenPGPFile, self).__init__()
            self.rawfile = fileobj_or_list

            #try and load the packets as-is
            try:
                self.read_packets()

            #couldn't load the packets, so try reading them as armored text
            except ValueError:
                self.rawfile = self.armor_to_bytes(fileobj_or_list)
                self.read_packets()

        #just set the given list
        else:
            super(OpenPGPFile, self).__init__(fileobj_or_list)

    def __getslice__(self, *args):
        result = super(OpenPGPFile, self).__getslice__(*args)
        result = OpenPGPFile(result)
        result.rawfile = self.rawfile
        return result

    def read_signature(self, body_start, body_len, msg_body=""):
        """
        Specification:
        https://tools.ietf.org/html/rfc4880#section-5.2

        Signature Types:
        ID           Signature type
        --           ---------
         0 (0x00)  - Signature of a binary document
         1 (0x01)  - Signature of a canonical text document
         2 (0x02)  - Standalone signature
        16 (0x10)  - Generic certification of a User ID and Public-Key packet
        17 (0x11)  - Persona certification of a User ID and Public-Key packet
        18 (0x12)  - Casual certification of a User ID and Public-Key packet
        19 (0x13)  - Positive certification of a User ID and Public-Key packet
        24 (0x18)  - Subkey Binding Signature
        25 (0x19)  - Primary Key Binding Signature
        31 (0x1F)  - Signature directly on a key
        32 (0x20)  - Key revocation signature
        40 (0x28)  - Subkey revocation signature
        48 (0x30)  - Certification revocation signature
        64 (0x40)  - Timestamp signature
        80 (0x50)  - Third-Party Confirmation signature

        Public Key Algorithms:
        ID           Algorithm
        --           ---------
        1          - RSA (Encrypt or Sign)
        2          - RSA Encrypt-Only
        3          - RSA Sign-Only
        16         - Elgamal (Encrypt-Only)
        17         - DSA (Digital Signature Algorithm)
        18         - ECDH public key algorithm
        19         - ECDSA public key algorithm
        20         - Reserved (formerly Elgamal Encrypt or Sign)
        21         - Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
        100 to 110 - Private/Experimental algorithm

        Hash Algorithms:
        ID           Algorithm
        --           ---------
        1          - MD5
        2          - SHA1
        3          - RIPEMD160
        4          - Reserved
        5          - Reserved
        6          - Reserved
        7          - Reserved
        8          - SHA256
        9          - SHA384
        10         - SHA512
        11         - SHA224
        100 to 110 - Private/Experimental algorithm

        Subpacket Types:
        ID           Type
        --           ---------
        0          - Reserved
        1          - Reserved
        2          - Signature Creation Time
        3          - Signature Expiration Time
        4          - Exportable Certification
        5          - Trust Signature
        6          - Regular Expression
        7          - Revocable
        8          - Reserved
        9          - Key Expiration Time
        10         - Placeholder for backward compatibility
        11         - Preferred Symmetric Algorithms
        12         - Revocation Key
        13         - Reserved
        14         - Reserved
        15         - Reserved
        16         - Issuer
        17         - Reserved
        18         - Reserved
        19         - Reserved
        20         - Notation Data
        21         - Preferred Hash Algorithms
        22         - Preferred Compression Algorithms
        23         - Key Server Preferences
        24         - Preferred Key Server
        25         - Primary User ID
        26         - Policy URI
        27         - Key Flags
        28         - Signer's User ID
        29         - Reason for Revocation
        30         - Features
        31         - Signature Target
        32         - Embedded Signature
        100 To 110 - Private or experimental

        Revocation Codes:
        ID           Reason
        --           ---------
        0          - No reason specified (key revocations or cert revocations)
        1          - Key is superseded (key revocations)
        2          - Key material has been compromised (key revocations)
        3          - Key is retired and no longer used (key revocations)
        32         - User ID information is no longer valid (cert revocations)
        100-110    - Private Use

        Return Format:
        {
            #standard packet values
            "tag_id": 2,
            "tag_name": "Signature",
            "body_start": 0,
            "body_len": 123,

            #errors (if any)
            "error": True,
            "error_msg": ["Error msg 1", "Error msg 2"],

            #signature packet values
            "version": 3 or 4,
            "signature_type_id": 16,
            "signature_type_name": "Generic certification of a User ID and Public-Key packet",
            "data": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
            "hash_check": "dead",
            "hash_algo_id": 8,
            "hash_algo_name": "SHA256",
            "pubkey_algo_id": 1,
            "pubkey_algo_name": "RSA (Encrypt or Sign)",

            #RSA specific (algo_ids 1, 3)
            "signature": "deadbeefdeadbeef",

            #DSA and ECDSA specific (algo_id 17)
            "signature_r": "deadbeefdeadbeef",
            "signature_s": "deadbeefdeadbeef",

            #version 3 specific values
            "creation_time": 1234567890,
            "key_id": "deadbeefdeadbeef",

            #version 4 specific values
            "subpackets": [
                {
                    #standard subpacket values (i.e. always included)
                    "type_id": 2,
                    "type_name": "Signature Creation Time",
                    "critical": True or False,
                    "hashed": True or False,

                    #errors (if any)
                    "error": True,
                    "error_msg": ["Error msg 1", "Error msg 2"],

                    #Signature Creation Time specific (type_id 2)
                    "creation_time": 1234567890,

                    #Signature Expiration Time specific (type_id 3)
                    "expiration_time": 1234567890,

                    #Exportable Certification specific (type_id 4)
                    "exportable": True or False,

                    #Trust Signature specific (type_id 5)
                    "level": 1,
                    "amount": 255,

                    #Regular Expression specific (type_id 6)
                    "regex": "abc*",

                    #Revocable specific (type_id 7)
                    "revocable": True or False,

                    #Key Expiration Time specific (type_id 9)
                    "expiration_time": 1234567890,

                    #Preferred Symmetric Algorithms specific (type_id 11)
                    "algos": [1, 2, 3, ...],

                    #Revocation Key specific (type_id 12)
                    "sensitive": True or False,
                    "pubkey_algo": 1,
                    "fingerprint": "deadbeefdeadbeefdeadbeefdeadbeef",

                    #Issuer specific (type_id 16)
                    "key_id": "deadbeefdeadbeef",

                    #Notation Data specific (type_id 20)
                    "human_readable": True or False,
                    "name": "<string>",
                    "value": "<string>",

                    #Preferred Hash Algorithms specific (type_id 21)
                    "algos": [1, 2, 3, ...],

                    #Preferred Compression Algorithms specific (type_id 22)
                    "algos": [1, 2, 3, ...],

                    #Key Server Preferences specific (type_id 23)
                    "no_modify": True or False,

                    #Preferred Key Server specific (type_id 24)
                    "keyserver": "keys.gnupg.net",

                    #Primary User ID specific (type_id 25)
                    "is_primary": True or False,

                    #Policy URI specific (type_id 26)
                    "uri": "https://sks-keyservers.net/",

                    #Key Flags specific (type_id 27)
                    "can_certify": True or False,
                    "can_sign": True or False,
                    "can_encrypt_communication": True or False,
                    "can_encrypt_storage": True or False,
                    "can_authenticate": True or False,
                    "private_might_be_split": True or False,
                    "private_might_be_shared": True or False,

                    #Signer's User ID specific (type_id 28)
                    "user_id": "John Doe (johndoe1234) <john.doe@example.com>",

                    #Reason for Revocation specific (type_id 29)
                    "code_id": 1,
                    "code_name": "Key is superseded",
                    "reason": "<string>",

                    #Features specific (type_id 30)
                    "modification_detection": True or False,

                    #Signature Target specific (type_id 31)
                    "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
                    "hash_algo": 8,
                    "pubkey_algo": 1,

                    #Embedded Signature specific (type_id 32)
                    "signature": {...}, #nested signature dict
                },
                ...
            ],
        }
        """
        result = {
            "tag_id": 2,
            "tag_name": "Signature",
            "body_start": body_start,
            "body_len": body_len,
        }

        #version
        self.rawfile.seek(body_start)
        version = ord(self.rawfile.read(1))
        if version not in [3, 4]:
            result['error'] = True
            result.setdefault("error_msg", []).append("Signature version is invalid ({}).".format(version))
            return result
        result['version'] = version

        #signature body length (version 3 only)
        if version == 3:
            sig_header_len = ord(self.rawfile.read(1))
            if sig_header_len != 5:
                result['error'] = True
                result.setdefault("error_msg", []).append("Signature body ({} bytes) not 5 bytes long.".format(sig_header_len))
                return result

        #signature type
        signature_type_id = ord(self.rawfile.read(1))
        try:
            signature_type_name = {
                0: "Signature of a binary document",
                1: "Signature of a canonical text document",
                2: "Standalone signature",
                16: "Generic certification",
                17: "Persona certification",
                18: "Casual certification",
                19: "Positive certification",
                24: "Subkey Binding",
                25: "Primary Key Binding",
                31: "Signature directly on a key",
                32: "Key revocation",
                40: "Subkey revocation",
                48: "Certification revocation",
                64: "Timestamp",
                80: "Third-Party Confirmation",
            }[signature_type_id]
        except KeyError:
            signature_type_name = "Unknown"
            result['error'] = True
            result.setdefault("error_msg", []).append("Signature type ({}) not recognized.".format(signature_type_id))
        result['signature_type_id'] = signature_type_id
        result['signature_type_name'] = signature_type_name

        #creation time (version 3 only)
        if version == 3:
            creation_bytes = self.rawfile.read(4)
            creation_time = int(creation_bytes.encode('hex'), 16)
            result['creation_time'] = creation_time

        #signer key_id (version 3 only)
        if version == 3:
            key_id = self.rawfile.read(8).encode("hex")
            result['key_id'] = key_id

        #public key algorithm
        pubkey_algo_id = ord(self.rawfile.read(1))
        try:
            pubkey_algo_name = {
                1: "RSA (Encrypt or Sign)",
                2: "RSA Encrypt-Only",
                3: "RSA Sign-Only",
                16: "Elgamal (Encrypt-Only)",
                17: "DSA (Digital Signature Algorithm)",
                18: "ECDH public key algorithm",
                19: "ECDSA public key algorithm",
                20: "Reserved (formerly Elgamal Encrypt or Sign)",
                21: "Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)",
                22: "EdDSA public key algorithm",
                100: "Private or experimental",
                101: "Private or experimental",
                102: "Private or experimental",
                103: "Private or experimental",
                104: "Private or experimental",
                105: "Private or experimental",
                106: "Private or experimental",
                107: "Private or experimental",
                108: "Private or experimental",
                109: "Private or experimental",
                110: "Private or experimental",
            }[pubkey_algo_id]
        except KeyError:
            pubkey_algo_name = "Unknown"
            result['error'] = True
            result.setdefault("error_msg", []).append("Public-Key algorithm ({}) not recognized.".format(pubkey_algo_id))
        result['pubkey_algo_id'] = pubkey_algo_id
        result['pubkey_algo_name'] = pubkey_algo_name

        #hash algorithm
        hash_algo_id = ord(self.rawfile.read(1))
        try:
            hash_algo_name = {
                1: "MD5",
                2: "SHA1",
                3: "RIPEMD160",
                4: "Reserved",
                5: "Reserved",
                6: "Reserved",
                7: "Reserved",
                8: "SHA256",
                9: "SHA384",
                10: "SHA512",
                11: "SHA224",
            }[hash_algo_id]
        except KeyError:
            hash_algo_name = "Unknown"
            result['error'] = True
            result.setdefault("error_msg", []).append("Hash algorithm ({}) not recognized.".format(hash_algo_id))
        result['hash_algo_id'] = hash_algo_id
        result['hash_algo_name'] = hash_algo_name

        #subpackets (version 4 only)
        if version == 4:

            #hashed subpackets length
            hashed_subpacket_len_bytes = self.rawfile.read(2)
            hashed_subpacket_len = int(hashed_subpacket_len_bytes.encode('hex'), 16)
            hashed_subpacket_end = self.rawfile.tell() + hashed_subpacket_len

            #make sure the section length is not over the end point
            if hashed_subpacket_end > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("Hashed subpacket section overflows the overall length.")
                hashed_subpacket_end = body_start + body_len

            #hashed subpackets
            subpackets_raw = []
            while self.rawfile.tell() < hashed_subpacket_end:

                #one byte length
                first_octet = ord(self.rawfile.read(1))
                if first_octet < 192:
                    subpacket_len = first_octet

                #two bytes length
                elif first_octet >= 192 and first_octet < 255:
                    second_octet = ord(self.rawfile.read(1))
                    subpacket_len = ((first_octet - 192) << 8) + second_octet + 192

                #four bytes length
                elif first_octet == 255:
                    four_bytes = self.rawfile.read(4)
                    subpacket_len = int(four_bytes.encode('hex'), 16)

                #make sure the subpacket length is not over the end point
                if self.rawfile.tell() + subpacket_len > hashed_subpacket_end:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Hashed subpacket length overflows the overall length.")
                    subpacket_len = hashed_subpacket_end - self.rawfile.tell()

                #save the position and length of the subpacket
                subpacket_start = self.rawfile.tell()
                self.rawfile.seek(subpacket_start + subpacket_len)
                subpackets_raw.append([True, subpacket_start, subpacket_len])

            #hashed subpackets length
            unhashed_subpacket_len_bytes = self.rawfile.read(2)
            unhashed_subpacket_len = int(unhashed_subpacket_len_bytes.encode('hex'), 16)
            unhashed_subpacket_end = self.rawfile.tell() + unhashed_subpacket_len

            #make sure the section length is not over the end point
            if unhashed_subpacket_end > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("Unhashed subpacket section overflows the overall length.")
                unhashed_subpacket_end = body_start + body_len

            #hashed subpackets
            while self.rawfile.tell() < unhashed_subpacket_end:

                #one byte length
                first_octet = ord(self.rawfile.read(1))
                if first_octet < 192:
                    subpacket_len = first_octet

                #two bytes length
                elif first_octet >= 192 and first_octet < 255:
                    second_octet = ord(self.rawfile.read(1))
                    subpacket_len = ((first_octet - 192) << 8) + second_octet + 192

                #four bytes length
                elif first_octet == 255:
                    four_bytes = self.rawfile.read(4)
                    subpacket_len = int(four_bytes.encode('hex'), 16)

                #make sure the subpacket length is not over the end point
                if self.rawfile.tell() + subpacket_len > unhashed_subpacket_end:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Unhashed subpacket length overflows the overall length.")
                    subpacket_len = unhashed_subpacket_end - self.rawfile.tell()

                #save the position and length of the subpacket
                subpacket_start = self.rawfile.tell()
                self.rawfile.seek(subpacket_start + subpacket_len)
                subpackets_raw.append([False, subpacket_start, subpacket_len])

            #parse subpackets
            result['subpackets'] = []
            for is_hashed, subpacket_start, subpacket_len in subpackets_raw:

                #create the base subpacket dict
                subpacket = {"hashed": is_hashed}
                self.rawfile.seek(subpacket_start)
                first_octet = ord(self.rawfile.read(1))

                #critical flag
                critical = first_octet >> 7 == 1
                subpacket['critical'] = critical

                #subpacket type
                type_id = first_octet & 0x7F
                try:
                    type_name = {
                        2: "Signature Creation Time",
                        3: "Signature Expiration Time",
                        4: "Exportable Certification",
                        5: "Trust Signature",
                        6: "Regular Expression",
                        7: "Revocable",
                        9: "Key Expiration Time",
                        10: "Placeholder for backward compatibility",
                        11: "Preferred Symmetric Algorithms",
                        12: "Revocation Key",
                        16: "Issuer",
                        20: "Notation Data",
                        21: "Preferred Hash Algorithms",
                        22: "Preferred Compression Algorithms",
                        23: "Key Server Preferences",
                        24: "Preferred Key Server",
                        25: "Primary User ID",
                        26: "Policy URI",
                        27: "Key Flags",
                        28: "Signer's User ID",
                        29: "Reason for Revocation",
                        30: "Features",
                        31: "Signature Target",
                        32: "Embedded Signature",
                        100: "Private or experimental",
                        101: "Private or experimental",
                        102: "Private or experimental",
                        103: "Private or experimental",
                        104: "Private or experimental",
                        105: "Private or experimental",
                        106: "Private or experimental",
                        107: "Private or experimental",
                        108: "Private or experimental",
                        109: "Private or experimental",
                        110: "Private or experimental",
                    }[type_id]
                except KeyError:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Subpacket type ({}) not recognized.".format(type_id))
                    subpacket['error'] = True
                    subpacket.setdefault("error_msg", []).append("Subpacket type ({}) not recognized.".format(type_id))
                    continue
                subpacket['type_id'] = type_id
                subpacket['type_name'] = type_name

                #Signature Creation Time
                if type_id == 2:
                    creation_bytes = self.rawfile.read(4)
                    creation_time = int(creation_bytes.encode('hex'), 16)
                    subpacket['creation_time'] = creation_time

                #Signature Expiration Time
                elif type_id == 3:
                    expiration_bytes = self.rawfile.read(4)
                    expiration_time = int(expiration_bytes.encode('hex'), 16)
                    subpacket['expiration_time'] = expiration_time

                #Exportable Certification
                elif type_id == 4:
                    exportable = ord(self.rawfile.read(1)) == 1
                    subpacket['exportable'] = exportable

                #Trust Signature
                elif type_id == 5:
                    trust_level = ord(self.rawfile.read(1))
                    trust_amount = ord(self.rawfile.read(1))
                    subpacket['level'] = trust_level
                    subpacket['amount'] = trust_amount

                #Regular Expression
                elif type_id == 6:
                    regex_str = self.rawfile.read(subpacket_len - 1)
                    subpacket['regex'] = regex_str

                #Revocable
                elif type_id == 7:
                    revocable = ord(self.rawfile.read(1)) == 1
                    subpacket['revocable'] = revocable

                #Key Expiration Time
                elif type_id == 9:
                    expiration_bytes = self.rawfile.read(4)
                    expiration_time = int(expiration_bytes.encode('hex'), 16)
                    subpacket['expiration_time'] = expiration_time

                #Preferred Symmetric Algorithms
                elif type_id == 11:
                    algo_bytes = self.rawfile.read(subpacket_len - 1)
                    subpacket['algos'] = []
                    for a in algo_bytes:
                        subpacket['algos'].append(ord(a))

                #Revocation Key
                elif type_id == 12:

                    #revocation class
                    revoke_class = ord(self.rawfile.read(1))
                    if revoke_class >> 7 != 1:
                        result['error'] = True
                        result.setdefault("error_msg", []).append("Revoke class must start with a 1 bit.")
                        subpacket['error'] = True
                        subpacket.setdefault("error_msg", []).append("Revoke class must start with a 1 bit.")
                    sensitive = revoke_class & 0x40 >> 6 == 1
                    subpacket['sensitive'] = sensitive

                    #public key algorithm
                    pubkey_algo = ord(self.rawfile.read(1))
                    subpacket['pubkey_algo'] = pubkey_algo

                    #revocation key fingerprint
                    fingerprint = self.rawfile.read(20).encode("hex")
                    subpacket['fingerprint'] = fingerprint

                #Issuer
                elif type_id == 16:
                    key_id = self.rawfile.read(8).encode("hex")
                    subpacket['key_id'] = key_id

                #Notation Data
                elif type_id == 20:

                    #flags (only human_readable is defined)
                    flags = int(self.rawfile.read(4).encode('hex'), 16)
                    human_readable = flags >> 31 == 1
                    subpacket['human_readable'] = human_readable

                    #name and value
                    name_len = int(self.rawfile.read(2).encode('hex'), 16)
                    value_len = int(self.rawfile.read(2).encode('hex'), 16)
                    if self.rawfile.tell() + name_len > subpacket_start + subpacket_len:
                        result['error'] = True
                        result.setdefault("error_msg", []).append("Subpacket name overflows the overall length.")
                        subpacket['error'] = True
                        subpacket.setdefault("error_msg", []).append("Subpacket name overflows the overall length.")
                        name_len = max(0, subpacket_len - (self.rawfile.tell() - subpacket_start))
                        value_len = 0
                    elif self.rawfile.tell() + name_len + value_len > subpacket_start + subpacket_len:
                        result['error'] = True
                        result.setdefault("error_msg", []).append("Subpacket value overflows the overall length.")
                        subpacket['error'] = True
                        subpacket.setdefault("error_msg", []).append("Subpacket value overflows the overall length.")
                        value_len = max(0, subpacket_len - (self.rawfile.tell() - subpacket_start))
                    subpacket['name'] = self.rawfile.read(name_len)
                    subpacket['value'] = self.rawfile.read(value_len)

                #Preferred Hash Algorithms
                elif type_id == 21:
                    algo_bytes = self.rawfile.read(subpacket_len - 1)
                    subpacket['algos'] = []
                    for a in algo_bytes:
                        subpacket['algos'].append(ord(a))

                #Preferred Compression Algorithms
                elif type_id == 22:
                    algo_bytes = self.rawfile.read(subpacket_len - 1)
                    subpacket['algos'] = []
                    for a in algo_bytes:
                        subpacket['algos'].append(ord(a))

                #Key Server Preferences (only first bit is defined)
                elif type_id == 23:
                    no_modify = ord(self.rawfile.read(1)) & 0x80 == 0x80
                    subpacket['no_modify'] = no_modify

                #Preferred Key Server
                elif type_id == 24:
                    keyserver = self.rawfile.read(subpacket_len - 1)
                    subpacket['keyserver'] = keyserver

                #Primary User ID
                elif type_id == 25:
                    is_primary = ord(self.rawfile.read(1)) == 1
                    subpacket['is_primary'] = is_primary

                #Policy URI
                elif type_id == 26:
                    policy_uri = self.rawfile.read(subpacket_len - 1)
                    subpacket['uri'] = policy_uri

                #Key Flags (only first octet has defined flags)
                elif type_id == 27:
                    flags = ord(self.rawfile.read(1))
                    subpacket['can_certify'] =               flags & 0x01 == 0x01
                    subpacket['can_sign'] =                  flags & 0x02 == 0x02
                    subpacket['can_encrypt_communication'] = flags & 0x04 == 0x04
                    subpacket['can_encrypt_storage'] =       flags & 0x08 == 0x08
                    subpacket['can_authenticate'] =          flags & 0x20 == 0x20
                    subpacket['private_might_be_split'] =    flags & 0x10 == 0x10
                    subpacket['private_might_be_shared'] =   flags & 0x80 == 0x80

                #Signer's User ID
                elif type_id == 28:
                    user_id = self.rawfile.read(subpacket_len - 1)
                    subpacket['user_id'] = user_id

                #Reason for Revocation
                elif type_id == 29:

                    #revocation code
                    code_id = ord(self.rawfile.read(1))
                    try:
                        code_name = {
                            0: "No reason specified",
                            1: "Key is superseded",
                            2: "Key material has been compromised",
                            3: "Key is retired and no longer used",
                            32: "User ID information is no longer valid",
                        }[code_id]
                    except KeyError:
                        result['error'] = True
                        result.setdefault("error_msg", []).append("Revocation code ({}) not recognized.".format(code_id))
                        subpacket['error'] = True
                        subpacket.setdefault("error_msg", []).append("Revocation code ({}) not recognized.".format(code_id))
                        code_name = "Unknown"
                    subpacket['code_id'] = code_id
                    subpacket['code_name'] = code_name

                    #revocation reason
                    reason = self.rawfile.read(subpacket_len - 2)
                    subpacket['reason'] = reason

                #Features (only first bit is defined)
                elif type_id == 30:
                    modification_detection = ord(self.rawfile.read(1)) & 0x01 == 0x01
                    subpacket['modification_detection'] = modification_detection

                #Signature Target
                elif type_id == 31:
                    pubkey_algo = ord(self.rawfile.read(1))
                    hash_algo = ord(self.rawfile.read(1))
                    hash_result = self.rawfile.read(subpacket_len - 3).encode("hex")
                    subpacket['pubkey_algo'] = pubkey_algo
                    subpacket['hash_algo'] = hash_algo
                    subpacket['hash'] = hash_result

                #Embedded Signature
                elif type_id == 32:
                    sig_start = self.rawfile.tell()
                    sig_len = subpacket_len - 1
                    subpacket['signature'] = self.read_signature(sig_start, sig_len)

                result['subpackets'].append(subpacket)

            #go to the end of the subpacket section
            self.rawfile.seek(unhashed_subpacket_end)

        #hash check
        hash_check = self.rawfile.read(2).encode("hex")
        result['hash_check'] = hash_check

        #RSA signature
        if pubkey_algo_id in [1, 3]:

            #RSA signature value m**d mod n
            sig_len_bytes = self.rawfile.read(2)
            sig_len = int(sig_len_bytes.encode('hex'), 16)
            sig_numbytes = int(math.ceil(sig_len / 8.0))
            if self.rawfile.tell() + sig_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("RSA signature overflows the overall length.")
                sig_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            sig_bytes = self.rawfile.read(sig_numbytes)
            if len(sig_bytes):
                sig_int = int(sig_bytes.encode('hex'), 16)
                if sig_int >> sig_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("RSA signature has non-zero leading bits.")
                sig_hex = "{0:0{1}x}".format(sig_int, sig_numbytes * 2)
                result['signature'] = sig_hex

        #DSA signature
        elif pubkey_algo_id in [17, 19, 22]:

            #DSA value r
            r_len_bytes = self.rawfile.read(2)
            r_len = int(r_len_bytes.encode('hex'), 16)
            r_numbytes = int(math.ceil(r_len / 8.0))
            if self.rawfile.tell() + r_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("DSA signature r overflows the overall length.")
                r_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            r_bytes = self.rawfile.read(r_numbytes)
            if len(r_bytes):
                r_int = int(r_bytes.encode('hex'), 16)
                if r_int >> r_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("DSA signature r has non-zero leading bits.")
                r_hex = "{0:0{1}x}".format(r_int, r_numbytes * 2)
                result['signature_r'] = r_hex

            #DSA value s
            s_len_bytes = self.rawfile.read(2)
            s_len = int(s_len_bytes.encode('hex'), 16)
            s_numbytes = int(math.ceil(s_len / 8.0))
            if self.rawfile.tell() + s_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("DSA signature s overflows the overall length.")
                s_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            s_bytes = self.rawfile.read(s_numbytes)
            if len(s_bytes):
                s_int = int(s_bytes.encode('hex'), 16)
                if s_int >> s_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("DSA signature s has non-zero leading bits.")
                s_hex = "{0:0{1}x}".format(s_int, s_numbytes * 2)
                result['signature_s'] = s_hex

        #Reserved (formerly Elgamal Encrypt or Sign)
        elif pubkey_algo_id == 20:
            pass

        #Experimental
        elif pubkey_algo_id >= 100 and pubkey_algo_id <= 110:
            pass

        #reject all other types of signatures
        else:
            result['error'] = True
            result.setdefault("error_msg", []).append("Unsupported signature type ({}).".format(pubkey_algo_id))
            return result

        #binary data document data
        if signature_type_name == "Signature of a binary document":
            #find the closest data packet
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Literal Data":
                    self.rawfile.seek(self[i]['body_start'])
                    msg_body = self.rawfile.read(self[i]['body_len'])
                    break
                i = i - 1

        #text data document data
        elif signature_type_name == "Signature of a canonical text document":
            #find the closest data packet
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Literal Data":
                    self.rawfile.seek(self[i]['body_start'])
                    msg_body = self.rawfile.read(self[i]['body_len'])
                    break
                i = i - 1
            #convert linebreaks to \r\n
            if "\r" not in msg_body:
                msg_body = msg_body.replace("\n", "\r\n")

        #direct key signature
        elif signature_type_name  == "Signature directly on a key":
            #find the closest primary public key
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Key":
                    self.rawfile.seek(self[i]['body_start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['body_len'], 4).decode("hex")
                    msg_body = prefix + len_octets + self.rawfile.read(self[i]['body_len'])
                    break
                i = i - 1

        #user id/attribute document data
        elif signature_type_name in [
            "Generic certification",
            "Persona certification",
            "Casual certification",
            "Positive certification",
            "Certification revocation",
        ]:
            #find the closest primary public key
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Key":
                    self.rawfile.seek(self[i]['body_start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['body_len'], 4).decode("hex")
                    msg_body = prefix + len_octets + self.rawfile.read(self[i]['body_len'])
                    break
                i = i - 1

            #find the closest user id or attribute
            i = len(self) - 1
            while i >= 0:

                #user id packet
                if self[i]['tag_name'] == "User ID":

                    #no prefix for version 3
                    if version == 3:
                        prefix = ""
                        len_octets = ""

                    #version 4 prefix (0xB4)
                    elif version == 4:
                        prefix = "\xb4"
                        len_octets = "{0:0{1}x}".format(self[i]['body_len'], 8).decode("hex")

                    self.rawfile.seek(self[i]['body_start'])
                    msg_body += prefix + len_octets + self.rawfile.read(self[i]['body_len'])
                    break

                #user attribute packet
                elif self[i]['tag_name'] == "User Attribute":

                    #no prefix for version 3
                    if version == 3:
                        prefix = ""
                        len_octets = ""

                    #version 4 prefix (0xD1)
                    elif version == 4:
                        prefix = "\xd1"
                        len_octets = "{0:0{1}x}".format(self[i]['body_len'], 8).decode("hex")

                    self.rawfile.seek(self[i]['body_start'])
                    msg_body += prefix + len_octets + self.rawfile.read(self[i]['body_len'])
                    break

                i = i - 1

        #subkey binding document data
        elif signature_type_name in ["Subkey Binding", "Primary Key Binding"]:

            #find the closest primary public key
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Key":
                    self.rawfile.seek(self[i]['body_start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['body_len'], 4).decode("hex")
                    msg_body = prefix + len_octets + self.rawfile.read(self[i]['body_len'])
                    break
                i = i - 1

            #find the closest subkey
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Subkey":
                    self.rawfile.seek(self[i]['body_start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['body_len'], 4).decode("hex")
                    msg_body += prefix + len_octets + self.rawfile.read(self[i]['body_len'])
                    break
                i = i - 1

        #primary key revoking document data
        elif signature_type_name == "Key revocation":

            #find the closest primary public key
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Key":
                    self.rawfile.seek(self[i]['body_start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['body_len'], 4).decode("hex")
                    msg_body = prefix + len_octets + self.rawfile.read(self[i]['body_len'])
                    break
                i = i - 1

        #subkey revoking document data
        elif signature_type_name == "Subkey revocation":

            #find the closest primary public key
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Subkey":
                    self.rawfile.seek(self[i]['body_start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['body_len'], 4).decode("hex")
                    msg_body = prefix + len_octets + self.rawfile.read(self[i]['body_len'])
                    break
                i = i - 1

        #hash trailer
        if version == 3:
            trailer = "{0:0{1}x}".format(result['signature_type_id'], 2).decode("hex")
            trailer += "{0:0{1}x}".format(result['creation_time'], 8).decode("hex")
        elif version == 4:
            hash_len = hashed_subpacket_end - body_start
            self.rawfile.seek(body_start)
            trailer = self.rawfile.read(hash_len)
            trailer += "\x04\xff"
            trailer += "{0:0{1}x}".format(hash_len, 8).decode("hex")

        #build data contents
        data = msg_body + trailer
        result['data'] = data.encode("hex")

        #hash result
        if hash_algo_name == "MD5":
            h = hashlib.md5()
        elif hash_algo_name == "SHA1":
            h = hashlib.sha1()
        elif hash_algo_name == "RIPEMD160":
            h = hashlib.new('ripemd160')
        elif hash_algo_name == "SHA256":
            h = hashlib.sha256()
        elif hash_algo_name == "SHA384":
            h = hashlib.sha384()
        elif hash_algo_name == "SHA512":
            h = hashlib.sha512()
        elif hash_algo_name == "SHA224":
            h = hashlib.sha224()
        elif hash_algo_name == "Reserved":
            result['error'] = True
            result.setdefault("error_msg", []).append("Digest algorithm ({}) can't be checked.".format(result['hash_algo_id']))
            return result
        else:
            result['error'] = True
            result.setdefault("error_msg", []).append("Unknown digest algorithm ({}).".format(result['hash_algo_id']))
            return result
        h.update(data)
        result['hash'] = h.hexdigest()

        #validate hash_check
        if not result['hash'].startswith(hash_check):
            result['error'] = True
            result.setdefault("error_msg", []).append("Digest ({}) doesn't start with '{}'.".format(result['hash'], hash_check))
            return result

        return result

    def generate_signature(self, p):

        #version
        bytes = "{0:0{1}x}".format(p['version'], 2).decode("hex")

        #signature body length (version 3 only)
        if p['version'] == 3:
            bytes += "{0:0{1}x}".format(5, 2).decode("hex")

        #signature type
        bytes += "{0:0{1}x}".format(p['signature_type_id'], 2).decode("hex")

        #creation time (version 3 only)
        if p['version'] == 3:
            bytes += "{0:0{1}x}".format(p['creation_time'], 4).decode("hex")

        #signer key_id (version 3 only)
        if p['version'] == 3:
            bytes += p['key_id'].decode("hex")

        #public key algorithm
        bytes += "{0:0{1}x}".format(p['pubkey_algo_id'], 2).decode("hex")

        #hash algorithm
        bytes += "{0:0{1}x}".format(p['hash_algo_id'], 2).decode("hex")

        #subpackts (version 4 only)
        if p['version'] == 4:

            #generate bytes for each subpacket
            hashed_subpackets = ""
            unhashed_subpackets = ""
            for sp in p['subpackets']:

                #Signature Creation Time
                if sp['type_id'] == 2:
                    sp_bytes = "{0:0{1}x}".format(sp['creation_time'], 8).decode("hex")

                #Signature Expiration Time
                elif sp['type_id'] == 3:
                    sp_bytes = "{0:0{1}x}".format(sp['expiration_time'], 8).decode("hex")

                #Exportable Certification
                elif sp['type_id'] == 4:
                    sp_bytes = "\x01" if sp['exportable'] else "\x00"

                #Trust Signature
                elif sp['type_id'] == 5:
                    sp_bytes = "{0:0{1}x}".format(sp['level'], 2).decode("hex")
                    sp_bytes += "{0:0{1}x}".format(sp['amount'], 2).decode("hex")

                #Regular Expression
                elif sp['type_id'] == 6:
                    sp_bytes = sp['regex']

                #Revocable
                elif sp['type_id'] == 7:
                    sp_bytes = "\x01" if sp['revocable'] else "\x00"

                #Key Expiration Time
                elif sp['type_id'] == 9:
                    sp_bytes = "{0:0{1}x}".format(sp['expiration_time'], 8).decode("hex")

                #Preferred Symmetric Algorithms
                elif sp['type_id'] == 11:
                    sp_bytes = ""
                    for a in sp['algos']:
                        sp_bytes += "{0:0{1}x}".format(a, 2).decode("hex")

                #Revocation Key
                elif sp['type_id'] == 12:
                    sp_bytes = "\xc0" if sp['sensitive'] else "\x80"
                    sp_bytes += "{0:0{1}x}".format(sp['pubkey_algo'], 2).decode("hex")
                    sp_bytes += "{0:0{1}x}".format(sp['fingerprint'], 40).decode("hex")

                #Issuer
                elif sp['type_id'] == 16:
                    sp_bytes = sp['key_id'].decode("hex")

                #Notation Data
                elif sp['type_id'] == 20:
                    sp_bytes = "\x80\x00\x00\x00" if sp['human_readable'] else "\x00\x00\x00\x00"
                    sp_bytes += "{0:0{1}x}".format(len(sp['name']), 4).decode("hex")
                    sp_bytes += "{0:0{1}x}".format(len(sp['value']), 4).decode("hex")
                    sp_bytes += sp['name']
                    sp_bytes += sp['value']

                #Preferred Hash Algorithms
                elif sp['type_id'] == 21:
                    sp_bytes = ""
                    for a in sp['algos']:
                        sp_bytes += "{0:0{1}x}".format(a, 2).decode("hex")

                #Preferred Compression Algorithms
                elif sp['type_id'] == 22:
                    sp_bytes = ""
                    for a in sp['algos']:
                        sp_bytes += "{0:0{1}x}".format(a, 2).decode("hex")

                #Key Server Preferences (only first bit is defined)
                elif sp['type_id'] == 23:
                    sp_bytes = "\x80" if sp['no_modify'] else "\x00"

                #Preferred Key Server
                elif sp['type_id'] == 24:
                    sp_bytes = sp['keyserver']

                #Primary User ID
                elif sp['type_id'] == 25:
                    sp_bytes = "\x01" if sp['is_primary'] else "\x00"

                #Policy URI
                elif sp['type_id'] == 26:
                    sp_bytes = sp['uri']

                #Key Flags (only first octet has defined flags)
                elif sp['type_id'] == 27:
                    flags = 0
                    flags |= 0x01 if sp['can_certify'] else 0x00
                    flags |= 0x02 if sp['can_sign'] else 0x00
                    flags |= 0x04 if sp['can_encrypt_communication'] else 0x00
                    flags |= 0x08 if sp['can_encrypt_storage'] else 0x00
                    flags |= 0x20 if sp['can_authenticate'] else 0x00
                    flags |= 0x10 if sp['private_might_be_split'] else 0x00
                    flags |= 0x80 if sp['private_might_be_shared'] else 0x00
                    sp_bytes = "{0:0{1}x}".format(flags, 2).decode("hex")

                #Signer's User ID
                elif sp['type_id'] == 28:
                    sp_bytes = sp['keyserver']

                #Reason for Revocation
                elif sp['type_id'] == 29:
                    sp_bytes = "{0:0{1}x}".format(sp['code_id'], 2).decode("hex")
                    sp_bytes += sp['reason']

                #Features (only first bit is defined)
                elif sp['type_id'] == 30:
                    sp_bytes = "\x01" if sp['modification_detection'] else "\x00"

                #Signature Target
                elif sp['type_id'] == 31:
                    sp_bytes = "{0:0{1}x}".format(sp['pubkey_algo'], 2).decode("hex")
                    sp_bytes += "{0:0{1}x}".format(sp['hash_algo'], 2).decode("hex")
                    sp_bytes += sp['hash'].decode("hex")

                #Embedded Signature
                elif sp['type_id'] == 32:
                    sp_bytes = self.generate_signature(sp['signature'])

                #calculate subpacket length
                sp_header = ""
                sp_len = len(sp_bytes) + 1

                #one byte length
                if sp_len < 192:
                    sp_header += "{0:0{1}x}".format(sp_len, 2).decode("hex")

                #two bytes length
                elif sp_len >= 192 and sp_len <= 16575:
                    octets = (sp_len - 192) | 0xC000
                    sp_header += "{0:0{1}x}".format(octets, 4).decode("hex")

                #five bytes length
                elif sp_len > 16575:
                    sp_header += "ff{0:0{1}x}".format(sp_len, 8).decode("hex")

                #add type and critical flag
                sp_type = sp['type_id']
                if sp['critical']:
                    sp_type |= 0x80
                sp_header += "{0:0{1}x}".format(sp_type, 2).decode("hex")

                #add to hashed or unhashed subpackets
                if sp['hashed']:
                    hashed_subpackets += sp_header + sp_bytes
                else:
                    unhashed_subpackets += sp_header + sp_bytes

            #calculate lengths
            hashed_len = "{0:0{1}x}".format(len(hashed_subpackets), 4).decode("hex")
            unhashed_len = "{0:0{1}x}".format(len(unhashed_subpackets), 4).decode("hex")

            bytes += hashed_len + hashed_subpackets
            bytes += unhashed_len + unhashed_subpackets

        #hash check
        bytes += p['hash_check'].decode("hex")

        #RSA signature
        if p['pubkey_algo_id'] in [1, 3]:

            #RSA signature value m**d mod n
            sig_int = int(p['signature'], 16)
            bytes += "{0:0{1}x}".format(sig_int.bit_length(), 4).decode("hex")
            bytes += p['signature'].decode("hex")

        #DSA signature
        elif p['pubkey_algo_id'] == 17:

            #DSA value r
            r_int = int(p['signature_r'], 16)
            bytes += "{0:0{1}x}".format(r_int.bit_length(), 4).decode("hex")
            bytes += p['signature_r'].decode("hex")

            #DSA value s
            s_int = int(p['signature_s'], 16)
            bytes += "{0:0{1}x}".format(s_int.bit_length(), 4).decode("hex")
            bytes += p['signature_s'].decode("hex")

        return bytes


    def read_onepasssig(self, body_start, body_len):
        """
        Specifications:
        https://tools.ietf.org/html/rfc4880#section-5.4

        Signature Types:
        ID           Signature type
        --           ---------
         0 (0x00)  - Signature of a binary document
         1 (0x01)  - Signature of a canonical text document
         2 (0x02)  - Standalone signature
        16 (0x10)  - Generic certification of a User ID and Public-Key packet
        17 (0x11)  - Persona certification of a User ID and Public-Key packet
        18 (0x12)  - Casual certification of a User ID and Public-Key packet
        19 (0x13)  - Positive certification of a User ID and Public-Key packet
        24 (0x18)  - Subkey Binding Signature
        25 (0x19)  - Primary Key Binding Signature
        31 (0x1F)  - Signature directly on a key
        32 (0x20)  - Key revocation signature
        40 (0x28)  - Subkey revocation signature
        48 (0x30)  - Certification revocation signature
        64 (0x40)  - Timestamp signature
        80 (0x50)  - Third-Party Confirmation signature

        Public Key Algorithms:
        ID           Algorithm
        --           ---------
        1          - RSA (Encrypt or Sign)
        2          - RSA Encrypt-Only
        3          - RSA Sign-Only
        16         - Elgamal (Encrypt-Only)
        17         - DSA (Digital Signature Algorithm)
        18         - ECDH public key algorithm
        19         - ECDSA public key algorithm
        20         - Reserved (formerly Elgamal Encrypt or Sign)
        21         - Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
        100 to 110 - Private/Experimental algorithm

        Hash Algorithms:
        ID           Algorithm
        --           ---------
        1          - MD5
        2          - SHA1
        3          - RIPEMD160
        4          - Reserved
        5          - Reserved
        6          - Reserved
        7          - Reserved
        8          - SHA256
        9          - SHA384
        10         - SHA512
        11         - SHA224
        100 to 110 - Private/Experimental algorithm

        Return Format:
        {
            #standard packet values
            "tag_id": 4,
            "tag_name": "One-Pass Signature",
            "body_start": 0,
            "body_len": 123,

            #errors (if any)
            "error": True,
            "error_msg": ["Error msg 1", "Error msg 2"],

            #one-pass signature packet values
            "version": 3,
            "signature_type_id": 16,
            "signature_type_name": "Generic certification of a User ID and Public-Key packet",
            "hash_algo_id": 8,
            "hash_algo_name": "SHA256",
            "pubkey_algo_id": 1,
            "pubkey_algo_name": "RSA (Encrypt or Sign)",
            "key_id": "deadbeefdeadbeef",
            "nested": True or False,
        }

        """
        result = {
            "tag_id": 4,
            "tag_name": "One-Pass Signature",
            "body_start": body_start,
            "body_len": body_len,
        }

        #version
        self.rawfile.seek(body_start)
        version = ord(self.rawfile.read(1))
        if version != 3:
            result['error'] = True
            result.setdefault("error_msg", []).append("One-Pass Signature version is invalid ({}).".format(version))
            return result
        result['version'] = version

        #signature type
        signature_type_id = ord(self.rawfile.read(1))
        try:
            signature_type_name = {
                0: "Signature of a binary document",
                1: "Signature of a canonical text document",
                2: "Standalone signature",
                16: "Generic certification",
                17: "Persona certification",
                18: "Casual certification",
                19: "Positive certification",
                24: "Subkey Binding",
                25: "Primary Key Binding",
                31: "Signature directly on a key",
                32: "Key revocation",
                40: "Subkey revocation",
                48: "Certification revocation",
                64: "Timestamp",
                80: "Third-Party Confirmation",
            }[signature_type_id]
        except KeyError:
            signature_type_name = "Unknown"
            result['error'] = True
            result.setdefault("error_msg", []).append("Signature type ({}) not recognized.".format(signature_type_id))
        result['signature_type_id'] = signature_type_id
        result['signature_type_name'] = signature_type_name

        #hash algorithm
        hash_algo_id = ord(self.rawfile.read(1))
        try:
            hash_algo_name = {
                1: "MD5",
                2: "SHA1",
                3: "RIPEMD160",
                4: "Reserved",
                5: "Reserved",
                6: "Reserved",
                7: "Reserved",
                8: "SHA256",
                9: "SHA384",
                10: "SHA512",
                11: "SHA224",
            }[hash_algo_id]
        except KeyError:
            hash_algo_name = "Unknown"
            result['error'] = True
            result.setdefault("error_msg", []).append("Hash algorithm ({}) not recognized.".format(hash_algo_id))
        result['hash_algo_id'] = hash_algo_id
        result['hash_algo_name'] = hash_algo_name

        #public key algorithm
        pubkey_algo_id = ord(self.rawfile.read(1))
        try:
            pubkey_algo_name = {
                1: "RSA (Encrypt or Sign)",
                2: "RSA Encrypt-Only",
                3: "RSA Sign-Only",
                16: "Elgamal (Encrypt-Only)",
                17: "DSA (Digital Signature Algorithm)",
                18: "ECDH public key algorithm",
                19: "ECDSA public key algorithm",
                20: "Reserved (formerly Elgamal Encrypt or Sign)",
                21: "Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)",
                22: "EdDSA public key algorithm",
                100: "Private or experimental",
                101: "Private or experimental",
                102: "Private or experimental",
                103: "Private or experimental",
                104: "Private or experimental",
                105: "Private or experimental",
                106: "Private or experimental",
                107: "Private or experimental",
                108: "Private or experimental",
                109: "Private or experimental",
                110: "Private or experimental",
            }[pubkey_algo_id]
        except KeyError:
            pubkey_algo_name = "Unknown"
            result['error'] = True
            result.setdefault("error_msg", []).append("Public-Key algorithm ({}) not recognized.".format(pubkey_algo_id))
        result['pubkey_algo_id'] = pubkey_algo_id
        result['pubkey_algo_name'] = pubkey_algo_name

        #signer key_id
        key_id = self.rawfile.read(8).encode("hex")
        result['key_id'] = key_id

        #is nested (0 means nested)
        nested_raw = ord(self.rawfile.read(1))
        result['nested'] = nested_raw == 0

        return result


    def read_pubkey(self, body_start, body_len):
        """
        Specifications:
        https://tools.ietf.org/html/rfc4880#section-5.5.1.1
        https://tools.ietf.org/html/rfc4880#section-5.5.2
        https://tools.ietf.org/html/rfc4880#section-9.1

        Public Key Algorithms:
        ID           Algorithm
        --           ---------
        1          - RSA (Encrypt or Sign)
        2          - RSA Encrypt-Only
        3          - RSA Sign-Only
        16         - Elgamal (Encrypt-Only)
        17         - DSA (Digital Signature Algorithm)
        18         - ECDH public key algorithm
        19         - ECDSA public key algorithm
        20         - Reserved (formerly Elgamal Encrypt or Sign)
        21         - Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
        100 to 110 - Private/Experimental algorithm

        Return Format:
        {
            #standard packet values
            "tag_id": 6,
            "tag_name": "Public-Key",
            "body_start": 0,
            "body_len": 123,

            #errors (if any)
            "error": True,
            "error_msg": ["Error msg 1", "Error msg 2"],

            #public key packet values
            "key_id": "deadbeefdeadbeef",
            "fingerprint": "deadbeefdeadbeefdeadbeefdeadbeef",
            "pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
            "version": 3 or 4,
            "algo_id": 1,
            "algo_name": "RSA (Encrypt or Sign)",
            "creation_time": 1234567890,
            "valid_days": 30, #version 3 only

            #RSA specific (algo_ids 1, 2, 3)
            "n": "deadbeef", #RSA public modulus n
            "e": "deadbeef", #RSA public encryption exponent e

            #Elgamal specific (algo_ids 16, 20)
            "p": "deadbeef", #Elgamal prime p
            "g": "deadbeef", #Elgamal group generator g

            #DSA specific (algo_id 17)
            "p": "deadbeef", #DSA prime p
            "q": "deadbeef", #DSA group order q (q is a prime divisor of p-1)
            "g": "deadbeef", #DSA group generator g
            "y": "deadbeef", #DSA public-key value y (= g**x mod p where x is secret)

            #ECDH specific (algo_id 18)
            #TODO

            #ECDSA specific (algo_id 19)
            "curve": "P-256", #(P-256|P-384|P-521)
            "x": "deadbeef",
            "y": "deadbeef",
        }
        """
        result = {
            "tag_id": 6,
            "tag_name": "Public-Key",
            "body_start": body_start,
            "body_len": body_len,
        }

        #version
        self.rawfile.seek(body_start)
        version = ord(self.rawfile.read(1))
        if version not in [3, 4]:
            result['error'] = True
            result.setdefault("error_msg", []).append("Public Key version is invalid ({}).".format(version))
            return result
        result['version'] = version

        #creation date
        creation_bytes = self.rawfile.read(4)
        creation_time = int(creation_bytes.encode('hex'), 16)
        result['creation_time'] = creation_time

        #expire days (version 3 only)
        if version == 3:
            valid_bytes = self.rawfile.read(2)
            valid_days = int(valid_bytes.encode('hex'), 16)
            result['valid_days'] = valid_days

        #algorithm
        algo_id = ord(self.rawfile.read(1))
        try:
            algo_name = {
                1: "RSA (Encrypt or Sign)",
                2: "RSA Encrypt-Only",
                3: "RSA Sign-Only",
                16: "Elgamal (Encrypt-Only)",
                17: "DSA (Digital Signature Algorithm)",
                18: "ECDH public key algorithm",
                19: "ECDSA public key algorithm",
                20: "Reserved (formerly Elgamal Encrypt or Sign)",
                21: "Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)",
                22: "EdDSA public key algorithm",
                100: "Private or experimental",
                101: "Private or experimental",
                102: "Private or experimental",
                103: "Private or experimental",
                104: "Private or experimental",
                105: "Private or experimental",
                106: "Private or experimental",
                107: "Private or experimental",
                108: "Private or experimental",
                109: "Private or experimental",
                110: "Private or experimental",
            }[algo_id]
        except KeyError:
            result['error'] = True
            result.setdefault("error_msg", []).append("Public-Key algorithm ({}) not recognized.".format(algo_id))
            result['algo_id'] = algo_id
            return result
        result['algo_id'] = algo_id
        result['algo_name'] = algo_name

        #RSA
        if algo_id in [1, 2, 3]:
            pem = ""

            #modulus
            n_len_bytes = self.rawfile.read(2)
            n_len = int(n_len_bytes.encode('hex'), 16)
            n_numbytes = int(math.ceil(n_len / 8.0))
            if self.rawfile.tell() + n_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("RSA modulus overflows the overall length.")
                n_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            n_bytes = self.rawfile.read(n_numbytes)
            if len(n_bytes):
                n_int = int(n_bytes.encode('hex'), 16)
                if n_int >> n_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("RSA modulus has non-zero leading bits.")
                n_hex = "{0:0{1}x}".format(n_int, n_numbytes * 2)
                result['n'] = n_hex
                pem += "0282{0:0{1}x}00".format(n_numbytes + 1, 4) + n_hex

            #exponent
            e_len_bytes = self.rawfile.read(2)
            e_len = int(e_len_bytes.encode('hex'), 16)
            e_numbytes = int(math.ceil(e_len / 8.0))
            if self.rawfile.tell() + e_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("RSA exponent overflows the overall length.")
                e_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            e_bytes = self.rawfile.read(e_numbytes)
            if len(e_bytes):
                e_int = int(e_bytes.encode('hex'), 16)
                if e_int >> e_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("RSA exponent has non-zero leading bits.")
                e_hex = "{0:0{1}x}".format(e_int, e_numbytes * 2)
                result['e'] = e_hex
                pem += "0282{0:0{1}x}".format(e_numbytes, 4) + e_hex

            #pem format
            pem_seq = "3082{0:0{1}x}".format(len(pem) / 2, 4) + pem
            pem_bitseq = "0382{0:0{1}x}00".format(len(pem_seq) / 2 + 1, 4) + pem_seq
            pem_rsa = "300d06092a864886f70d0101010500" + pem_bitseq
            pem_full = "3082{0:0{1}x}".format(len(pem_rsa) / 2, 4) + pem_rsa
            pem_bytes = pem_full.decode("hex")

        #Elgamal
        elif algo_id in [16, 20]:

            #prime p
            p_len_bytes = self.rawfile.read(2)
            p_len = int(p_len_bytes.encode('hex'), 16)
            p_numbytes = int(math.ceil(p_len / 8.0))
            if self.rawfile.tell() + p_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("Elgamal prime p overflows the overall length.")
                p_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            p_bytes = self.rawfile.read(p_numbytes)
            if len(p_bytes):
                p_int = int(p_bytes.encode('hex'), 16)
                if p_int >> p_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Elgamal prime p has non-zero leading bits.")
                p_hex = "{0:0{1}x}".format(p_int, p_numbytes * 2)
                result['p'] = p_hex

            #generator g
            g_len_bytes = self.rawfile.read(2)
            g_len = int(g_len_bytes.encode('hex'), 16)
            g_numbytes = int(math.ceil(g_len / 8.0))
            if self.rawfile.tell() + g_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("Elgamal generator g overflows the overall length.")
                g_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            g_bytes = self.rawfile.read(g_numbytes)
            if len(g_bytes):
                g_int = int(g_bytes.encode('hex'), 16)
                if g_int >> g_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Elgamal generator g has non-zero leading bits.")
                g_hex = "{0:0{1}x}".format(g_int, g_numbytes * 2)
                result['g'] = g_hex

            #public-key value y
            y_len_bytes = self.rawfile.read(2)
            y_len = int(y_len_bytes.encode('hex'), 16)
            y_numbytes = int(math.ceil(y_len / 8.0))
            if self.rawfile.tell() + y_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("Elgamal public-key value y overflows the overall length.")
                y_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            y_bytes = self.rawfile.read(y_numbytes)
            if len(y_bytes):
                y_int = int(y_bytes.encode('hex'), 16)
                if y_int >> y_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Elgamal public-key value y has non-zero leading bits.")
                y_hex = "{0:0{1}x}".format(y_int, y_numbytes * 2)
                result['y'] = y_hex

            #TODO: Make real pem bytes
            pem_bytes = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

        #DSA
        elif algo_id == 17:

            #prime p
            p_len_bytes = self.rawfile.read(2)
            p_len = int(p_len_bytes.encode('hex'), 16)
            p_numbytes = int(math.ceil(p_len / 8.0))
            if self.rawfile.tell() + p_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("DSA prime p overflows the overall length.")
                p_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            p_bytes = self.rawfile.read(p_numbytes)
            if len(p_bytes):
                p_int = int(p_bytes.encode('hex'), 16)
                if p_int >> p_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("DSA prime p has non-zero leading bits.")
                p_hex = "{0:0{1}x}".format(p_int, p_numbytes * 2)
                result['p'] = p_hex

            #group order q
            q_len_bytes = self.rawfile.read(2)
            q_len = int(q_len_bytes.encode('hex'), 16)
            q_numbytes = int(math.ceil(q_len / 8.0))
            if self.rawfile.tell() + q_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("DSA group order q overflows the overall length.")
                q_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            q_bytes = self.rawfile.read(q_numbytes)
            if len(q_bytes):
                q_int = int(q_bytes.encode('hex'), 16)
                if q_int >> q_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("DSA group order q has non-zero leading bits.")
                q_hex = "{0:0{1}x}".format(q_int, q_numbytes * 2)
                result['q'] = q_hex

            #generator g
            g_len_bytes = self.rawfile.read(2)
            g_len = int(g_len_bytes.encode('hex'), 16)
            g_numbytes = int(math.ceil(g_len / 8.0))
            if self.rawfile.tell() + g_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("DSA generator g overflows the overall length.")
                g_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            g_bytes = self.rawfile.read(g_numbytes)
            if len(g_bytes):
                g_int = int(g_bytes.encode('hex'), 16)
                if g_int >> g_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("DSA generator g has non-zero leading bits.")
                g_hex = "{0:0{1}x}".format(g_int, g_numbytes * 2)
                result['g'] = g_hex

            #public-key value y
            y_len_bytes = self.rawfile.read(2)
            y_len = int(y_len_bytes.encode('hex'), 16)
            y_numbytes = int(math.ceil(y_len / 8.0))
            if self.rawfile.tell() + y_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("DSA public-key value y overflows the overall length.")
                y_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            y_bytes = self.rawfile.read(y_numbytes)
            if len(y_bytes):
                y_int = int(y_bytes.encode('hex'), 16)
                if y_int >> y_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("DSA public-key value y has non-zero leading bits.")
                y_hex = "{0:0{1}x}".format(y_int, y_numbytes * 2)
                result['y'] = y_hex

            #TODO: Make real pem bytes
            pem_bytes = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

        #ECDH
        elif algo_id == 18:

            #curve oid
            oid_len = ord(self.rawfile.read(1))
            if self.rawfile.tell() + oid_len > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("ECDH OID length overflows the overall length.")
                oid_len = max(0, body_len - (self.rawfile.tell() - body_start))
            oid = self.rawfile.read(oid_len)
            try:
                curve_name = {
                    "2a8648ce3d030107":   "NIST curve P-256",
                    "2b81040022":         "NIST curve P-384",
                    "2b81040023":         "NIST curve P-521",
                    "2b8104000a":         "secp256k1",
                    "2b2403030208010107": "brainpoolP256r1",
                    "2b240303020801010b": "brainpoolP384r1",
                    "2b240303020801010d": "brainpoolP512r1",
                }[oid.encode("hex")]
            except KeyError:
                curve_name = "Unknown"
                result['error'] = True
                result.setdefault("error_msg", []).append("ECDH has unknown curve OID ('{}').".format(oid.encode("hex")))
            result['oid'] = oid
            result['curve_name'] = curve_name

            #public key coords
            coords_len_bytes = self.rawfile.read(2)
            coords_len = int(coords_len_bytes.encode('hex'), 16)
            coords_numbytes = int(math.ceil(coords_len / 8.0))
            if self.rawfile.tell() + coords_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("ECDH coords overflows the overall length.")
                coords_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            coords_bytes = self.rawfile.read(coords_numbytes)
            if len(coords_bytes):
                coords_int = int(coords_bytes.encode('hex'), 16)
                if coords_int >> coords_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("ECDH coords have non-zero leading bits.")
                coords_hex = "{0:0{1}x}".format(coords_int, coords_numbytes * 2)

                #uncompressed coordinates
                coords_x = coords_hex[1:(len(coords_hex) - 1)/2]
                coords_y = coords_hex[(len(coords_hex) - 1)/2:]
                result['x'] = coords_x
                result['y'] = coords_y

            #KDF parameters
            kdf_len = ord(self.rawfile.read(1))
            kdf_version = ord(self.rawfile.read(1))
            if kdf_version == 1:
                kdf_hash_id = ord(self.rawfile.read(1))
                kdf_algo_id = ord(self.rawfile.read(1))
                result['kdf_hash_id'] = kdf_hash_id
                result['kdf_algo_id'] = kdf_algo_id
            else:
                result['error'] = True
                result.setdefault("error_msg", []).append("ECDH version ({}) is not 1.".format(kdf_version))

            #TODO: Make real pem bytes
            pem_bytes = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

        #ECDSA
        elif algo_id == 19:

            #curve oid
            oid_len = ord(self.rawfile.read(1))
            if self.rawfile.tell() + oid_len > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("ECDSA OID length overflows the overall length.")
                oid_len = max(0, body_len - (self.rawfile.tell() - body_start))
            oid = self.rawfile.read(oid_len)
            try:
                curve_name = {
                    "2a8648ce3d030107":   "NIST curve P-256",
                    "2b81040022":         "NIST curve P-384",
                    "2b81040023":         "NIST curve P-521",
                    "2b8104000a":         "secp256k1",
                    "2b2403030208010107": "brainpoolP256r1",
                    "2b240303020801010b": "brainpoolP384r1",
                    "2b240303020801010d": "brainpoolP512r1",
                }[oid.encode("hex")]
            except KeyError:
                curve_name = "Unknown"
                result['error'] = True
                result.setdefault("error_msg", []).append("ECDSA has unknown curve OID ('{}').".format(oid.encode("hex")))
            result['oid'] = oid
            result['curve_name'] = curve_name

            #public key coords
            coords_len_bytes = self.rawfile.read(2)
            coords_len = int(coords_len_bytes.encode('hex'), 16)
            coords_numbytes = int(math.ceil(coords_len / 8.0))
            if self.rawfile.tell() + coords_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("ECDSA coords overflows the overall length.")
                coords_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            coords_bytes = self.rawfile.read(coords_numbytes)
            if len(coords_bytes):
                coords_int = int(coords_bytes.encode('hex'), 16)
                if coords_int >> coords_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("ECDSA coords have non-zero leading bits.")
                coords_hex = "{0:0{1}x}".format(coords_int, coords_numbytes * 2)

                #uncompressed coordinates
                coords_x = coords_hex[1:(len(coords_hex) - 1)/2]
                coords_y = coords_hex[(len(coords_hex) - 1)/2:]
                result['x'] = coords_x
                result['y'] = coords_y

            #TODO: Make real pem bytes
            pem_bytes = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

        #DH
        elif algo_id == 21:
            raise NotImplementedError("DH public key parsing is not implemented yet :(")

        #EdDSA
        elif algo_id == 22:

            #curve oid
            oid_len = ord(self.rawfile.read(1))
            if self.rawfile.tell() + oid_len > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("ECDSA OID length overflows the overall length.")
                oid_len = max(0, body_len - (self.rawfile.tell() - body_start))
            oid = self.rawfile.read(oid_len)
            try:
                curve_name = {
                    "2b06010401da470f01": "Ed25519",
                }[oid.encode("hex")]
            except KeyError:
                curve_name = "Unknown"
                result['error'] = True
                result.setdefault("error_msg", []).append("EdDSA has unknown curve OID ('{}').".format(oid.encode("hex")))
            result['oid'] = oid
            result['curve_name'] = curve_name

            #public key coords
            coords_len_bytes = self.rawfile.read(2)
            coords_len = int(coords_len_bytes.encode('hex'), 16)
            coords_numbytes = int(math.ceil(coords_len / 8.0))
            if self.rawfile.tell() + coords_numbytes > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("EdDSA coords overflows the overall length.")
                coords_numbytes = max(0, body_len - (self.rawfile.tell() - body_start))
            coords_bytes = self.rawfile.read(coords_numbytes)
            if len(coords_bytes):
                coords_int = int(coords_bytes.encode('hex'), 16)
                if coords_int >> coords_len != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("EdDSA coords have non-zero leading bits.")
                coords_hex = "{0:0{1}x}".format(coords_int, coords_numbytes * 2)

                #compressed format
                if coords_hex.startswith("40"):
                    result['x'] = coords_hex[1:]

                #uncompressed format
                elif coords_hex.startswith("04"):
                    result['x'] = coords_hex[1:(len(coords_hex) - 1)/2]
                    result['y'] = coords_hex[(len(coords_hex) - 1)/2:]

            #TODO: Make real pem bytes
            pem_bytes = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

        #private/experimental
        elif algo_id >= 100 and algo_id <= 110:
            pem_bytes = None

        #reject all other algorithms
        else:
            pem_bytes = None
            result['error'] = True
            result.setdefault("error_msg", []).append("Public Key algorithm is invalid ({}).".format(algo_id))

        #pem file
        if pem_bytes:
            p = base64.b64encode(pem_bytes)
            pem_b64 = "\n".join([p[i*64:(i+1)*64] for i in xrange(0, int(math.ceil(len(p)/64))+1)])
            pem_str = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----".format(pem_b64)
            result['pem'] = pem_str

        #fingerprint (version 3)
        if version == 3:
            #make sure this is an rsa public key
            if algo_id not in [1, 2, 3]:
                result['error'] = True
                result.setdefault("error_msg", []).append(
                    "Public Key algorithm ({}) is not RSA, which is required in version 3.".format(algo_id))
                return result
            body = "{}{}".format(n_bytes, e_bytes)
            result['fingerprint'] = hashlib.md5(body).hexdigest()
            result['key_id'] = result['n'][-16:]

        #fingerprint (version 4)
        elif version == 4:
            self.rawfile.seek(body_start)
            len_hex = "{0:0{1}x}".format(body_len, 4).decode("hex")
            body = "\x99{}{}".format(len_hex, self.rawfile.read(body_len))
            result['fingerprint'] = hashlib.sha1(body).hexdigest()
            result['key_id'] = result['fingerprint'][-16:]

        return result

    def generate_pubkey(self, p):
        #version
        bytes = "{0:0{1}x}".format(p['version'], 2).decode("hex")

        #creation time
        bytes += "{0:0{1}x}".format(p['creation_time'], 8).decode("hex")

        #valid days
        if p['version'] == 3:
            bytes += "{0:0{1}x}".format(p['valid_days'], 4).decode("hex")

        #algo_id
        bytes += "{0:0{1}x}".format(p['algo_id'], 2).decode("hex")

        #RSA
        if p['algo_id'] in [1, 2, 3]:

            #modulus
            modulus_int = int(p['n'], 16)
            bytes += "{0:0{1}x}".format(modulus_int.bit_length(), 4).decode("hex")
            bytes += p['n'].decode("hex")

            #exponent
            exponent_int = int(p['e'], 16)
            bytes += "{0:0{1}x}".format(exponent_int.bit_length(), 4).decode("hex")
            bytes += p['e'].decode("hex")

        #Elgamal
        elif p['algo_id'] in [16, 20]:
            raise NotImplementedError("Elgamal public key parsing is not implemented yet :(")

        #DSA
        elif p['algo_id'] == 17:
            raise NotImplementedError("DSA public key parsing is not implemented yet :(")

        #ECDH
        elif p['algo_id'] == 18:
            raise NotImplementedError("ECDH public key parsing is not implemented yet :(")

        #ECDSA
        elif p['algo_id'] == 19:
            raise NotImplementedError("ECDSA public key parsing is not implemented yet :(")

        #DH
        elif p['algo_id'] == 21:
            raise NotImplementedError("DH public key parsing is not implemented yet :(")

        return bytes

    def read_pubsubkey(self, body_start, body_len):
        """
        Specification:
        https://tools.ietf.org/html/rfc4880#section-5.5.1.2

        Return Format:
        Same as read_pubkey, except tag_id is 14 and tag_name is "Public-Subkey"
        """
        pubkey_result = self.read_pubkey(body_start, body_len)
        pubkey_result['tag_id'] = 14
        pubkey_result['tag_name'] = "Public-Subkey"
        return pubkey_result

    def generate_pubsubkey(self, p):
        return self.generate_pubkey(p)

    def read_userid(self, body_start, body_len):
        """
        Specification:
        https://tools.ietf.org/html/rfc4880#section-5.11

        Return Format:
        {
            #standard packet values
            "tag_id": 6,
            "tag_name": "User ID",
            "body_start": 0,
            "body_len": 123,

            #errors (if any)
            "error": True,
            "error_msg": ["Error msg 1", "Error msg 2"],

            #User ID specific fields
            "user_id": "John Doe (johndoe1234) <john.doe@example.com>",
        }
        """
        self.rawfile.seek(body_start)
        return {
            "tag_id": 13,
            "tag_name": "User ID",
            "body_start": body_start,
            "body_len": body_len,
            "user_id": self.rawfile.read(body_len),
        }

    def generate_userid(self, p):
        return p['user_id']

    def read_attribute(self, body_start, body_len):
        """
        Specification:
        https://tools.ietf.org/html/rfc4880#section-5.12

        Return Format:
        {
            #standard packet values
            "tag_id": 17,
            "tag_name": "User Attribute",
            "body_start": 0,
            "body_len": 123,

            #errors (if any)
            "error": True,
            "error_msg": ["Error msg 1", "Error msg 2"],

            #User Attribute specific fields
            "subpackets": [
                {
                    #standard subpacket values
                    "type_id": 1,
                    "type_name": "Image",

                    #errors (if any)
                    "error": True,
                    "error_msg": ["Error msg 1", "Error msg 2"],

                    #image specific values
                    "version": 1,
                    "encoding": "JPEG",
                    "image": "<base64_encoded_image>",
                },
                ...
            ],
        }
        """
        result = {
            "tag_id": 17,
            "tag_name": "User Attribute",
            "body_start": body_start,
            "body_len": body_len,
            "subpackets": [],
        }

        #read the user attribute subpackets
        self.rawfile.seek(body_start)
        while self.rawfile.tell() < (body_start + body_len):

            #one byte length
            first_octet = ord(self.rawfile.read(1))
            if first_octet < 192:
                subpacket_len = first_octet

            #two bytes length
            elif first_octet >= 192 and first_octet < 255:
                second_octet = ord(self.rawfile.read(1))
                subpacket_len = ((first_octet - 192) << 8) + second_octet + 192

            #four bytes length
            elif first_octet == 255:
                four_bytes = self.rawfile.read(4)
                subpacket_len = int(four_bytes.encode('hex'), 16)

            #make sure there's no overflow
            if self.rawfile.tell() + subpacket_len > body_start + body_len:
                result['error'] = True
                result.setdefault("error_msg", []).append("User Attribute subpacket overflows the overall length.")
                subpacket_len = max(0, body_len - (self.rawfile.tell() - body_start))

            #subpacket type
            type_id = ord(self.rawfile.read(1))
            subpacket = {"type_id": type_id}
            try:
                type_name = {
                    1: "Image",
                    100: "Private or experimental",
                    101: "Private or experimental",
                    102: "Private or experimental",
                    103: "Private or experimental",
                    104: "Private or experimental",
                    105: "Private or experimental",
                    106: "Private or experimental",
                    107: "Private or experimental",
                    108: "Private or experimental",
                    109: "Private or experimental",
                    110: "Private or experimental",
                }[type_id]
            except KeyError:
                result['error'] = True
                result.setdefault("error_msg", []).append("User Attribute subpacket type ({}) not recognized.".format(type_id))
                subpacket['error'] = True
                subpacket.setdefault("error_msg", []).append("User Attribute subpacket type ({}) not recognized.".format(type_id))
                type_name = "Unknown"
            subpacket['type_name'] = type_name

            #Image subpacket
            if type_id == 1:

                #get the header length
                header_len_bytes = "".join(reversed(self.rawfile.read(2))) #little endian
                header_len = int(header_len_bytes.encode('hex'), 16)
                if header_len != 16:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Image header size is invalid ({}).".format(header_len))
                    subpacket['error'] = True
                    subpacket.setdefault("error_msg", []).append("Image header size is invalid ({}).".format(header_len))
                    result['subpackets'].append(subpacket)
                    return result

                #get the header version
                header_version = ord(self.rawfile.read(1))
                if header_version != 1:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Image header version is invalid ({}).".format(header_version))
                    subpacket['error'] = True
                    subpacket.setdefault("error_msg", []).append("Image header version is invalid ({}).".format(header_version))
                subpacket['version'] = header_version

                #get image encoding
                image_encoding_id = ord(self.rawfile.read(1))
                try:
                    image_encoding = {
                        1: "JPEG",
                    }[image_encoding_id]
                except KeyError:
                    image_encoding = "Unknown"
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Image encoding ({}) not recognized.".format(image_encoding_id))
                    subpacket['error'] = True
                    subpacket.setdefault("error_msg", []).append("Image encoding ({}) not recognized.".format(image_encoding_id))
                subpacket['encoding'] = image_encoding

                #the rest of the header is blank
                header_remaining = self.rawfile.read(12)
                if int(header_remaining.encode('hex'), 16) != 0:
                    result['error'] = True
                    result.setdefault("error_msg", []).append("Image header remainder contains non-zero values.")

                #the rest of the subpacket is the image
                image_raw = self.rawfile.read(subpacket_len - header_len - 1)
                subpacket['image'] = base64.b64encode(image_raw)

            result['subpackets'].append(subpacket)

        return result

    def generate_attribute(self, p):
        #build subpackets
        attr_bytes = ""
        subpackets = []
        for sp in p['subpackets']:
            sp_bytes = ""

            #images
            if sp['type_id'] == 1:

                #encoding
                encoding_id = {
                    "JPEG": 1,
                    "Unknown": 0,
                }[sp['encoding']]

                #image subpacket
                sp_bytes += "{h_len}{h_ver}{encoding}{pad}{img}".format(
                    #header length (16 bytes, little endian)
                    h_len="1000".decode("hex"),
                    #header version
                    h_ver="{0:0{1}x}".format(sp['version'], 2).decode("hex"),
                    #encoding
                    encoding="{0:0{1}x}".format(encoding_id, 2).decode("hex"),
                    #remainder of header length
                    pad="{0:0{1}x}".format(0, 24).decode("hex"),
                    #raw image
                    img=base64.b64decode(sp['image']),
                )

            #calculate subpacket length (same a signature subpacket lengths)
            sp_header = ""
            sp_len = len(sp_bytes) + 1

            #one byte length
            if sp_len < 192:
                sp_header += "{0:0{1}x}".format(sp_len, 2).decode("hex")

            #two bytes length
            elif sp_len >= 192 and sp_len <= 8383:
                octets = (sp_len - 192) | 0xC000
                sp_header += "{0:0{1}x}".format(octets, 4).decode("hex")

            #five bytes length
            elif sp_len > 8383:
                sp_header += "ff{0:0{1}x}".format(sp_len, 8).decode("hex")

            #add type
            sp_header += "{0:0{1}x}".format(sp['type_id'], 2).decode("hex")

            #add to overall attribute bytes
            attr_bytes += sp_header + sp_bytes

        return attr_bytes

    def read_compressed(self, body_start, body_len):
        """
        Specification:
        https://tools.ietf.org/html/rfc4880#section-5.6
        https://tools.ietf.org/html/rfc4880#section-9.3

        Compression Algorithms:
        0          - Uncompressed
        1          - ZIP
        2          - ZLIB
        3          - BZip2
        100 to 110 - Private/Experimental algorithm

        Return Format:
        {
            #standard packet values
            "tag_id": 8,
            "tag_name": "Compressed Data",
            "body_start": 0,
            "body_len": 123,

            #errors (if any)
            "error": True,
            "error_msg": ["Error msg 1", "Error msg 2"],

            #decompressed packets
            "compression_algo_id": 1,
            "compression_algo_name": "ZIP",
            "packets": [
                {...},
                ...
            ],
        }
        """
        result = {
            "tag_id": 8,
            "tag_name": "Compressed Data",
            "body_start": body_start,
            "body_len": body_len,
            "packets": [],
        }

        #read the compression algo
        self.rawfile.seek(body_start)
        compression_algo_id = ord(self.rawfile.read(1))
        result['compression_algo_id'] = compression_algo_id
        try:
            compression_algo_name = {
                0: "Uncompressed",
                1: "ZIP",
                2: "ZLIB",
                3: "BZip2",
                100: "Private or experimental",
                101: "Private or experimental",
                102: "Private or experimental",
                103: "Private or experimental",
                104: "Private or experimental",
                105: "Private or experimental",
                106: "Private or experimental",
                107: "Private or experimental",
                108: "Private or experimental",
                109: "Private or experimental",
                110: "Private or experimental",
            }[compression_algo_id]
            result['compression_algo_name'] = compression_algo_name
        except KeyError:
            result['error'] = True
            result.setdefault("error_msg", []).append("Compression algorithm ({}) not recognized.".format(compression_algo_id))
            return result

        #Uncompressed
        if compression_algo_id == 0:
            decomp_file = tempfile.NamedTemporaryFile()
            decomp_file.write(self.rawfile.read(body_len-1))

        #ZIP
        elif compression_algo_id == 1:
            decompress = zlib.decompressobj(-zlib.MAX_WBITS)
            decompress_raw = decompress.decompress(self.rawfile.read(body_len-1))
            decomp_file = tempfile.NamedTemporaryFile()
            decomp_file.write(decompress_raw)
            decomp_file.write(decompress.flush())

        #ZLIB
        elif compression_algo_id == 2:
            decomp_file = tempfile.NamedTemporaryFile()
            decomp_file.write(zlib.decompress(self.rawfile.read(body_len-1)))

        #BZip2
        elif compression_algo_id == 3:
            decomp_file = tempfile.NamedTemporaryFile()
            decomp_file.write(bz2.decompress(self.rawfile.read(body_len-1)))

        #find uncompressed length
        decomp_len = decomp_file.tell()
        result['decompressed_len'] = decomp_len

        #parse the decompressed file
        decomp_file.seek(0)
        for packet in OpenPGPFile(decomp_file):
            result['packets'].append(packet)

        return result

    def read_literal(self, body_start, body_len):
        """
        Specification:
        https://tools.ietf.org/html/rfc4880#section-5.9

        Return Format:
        {
            #standard packet values
            "tag_id": 8,
            "tag_name": "Compressed Data",
            "body_start": 0,
            "body_len": 123,

            #errors (if any)
            "error": True,
            "error_msg": ["Error msg 1", "Error msg 2"],

            #decompressed packets
            "mode": "b", #"b", "t", or "u"
            "data": "...",
        }
        """
        result = {
            "tag_id": 11,
            "tag_name": "Literal Data",
            "body_start": body_start,
            "body_len": body_len,
        }

        #read the mode type
        self.rawfile.seek(body_start)
        result['mode'] = self.rawfile.read(1)
        if result['mode'] not in ['b', 't', 'u']:
            result['error'] = True
            result.setdefault("error_msg", []).append("Data mode ({}) not recognized.".format(result['mode']))

        #read the literal data
        result['data'] = self.rawfile.read(body_len-1)

        return result

    def read_packets(self):
        """
        Specification:
        https://tools.ietf.org/html/rfc4880#section-4.2
        https://tools.ietf.org/html/rfc4880#section-4.3

        Packet tag ids:
        0        -- Reserved - a packet tag MUST NOT have this value
        1        -- Public-Key Encrypted Session Key Packet
        2        -- Signature Packet
        3        -- Symmetric-Key Encrypted Session Key Packet
        4        -- One-Pass Signature Packet
        5        -- Secret-Key Packet
        6        -- Public-Key Packet
        7        -- Secret-Subkey Packet
        8        -- Compressed Data Packet
        9        -- Symmetrically Encrypted Data Packet
        10       -- Marker Packet
        11       -- Literal Data Packet
        12       -- Trust Packet
        13       -- User ID Packet
        14       -- Public-Subkey Packet
        17       -- User Attribute Packet
        18       -- Sym. Encrypted and Integrity Protected Data Packet
        19       -- Modification Detection Code Packet
        60 to 63 -- Private or Experimental Values
        """

        #get the file length
        self.rawfile.seek(0, os.SEEK_END)
        filelen = self.rawfile.tell()

        #go through and find all the packet headers
        i = 0
        while True:

            #break when at the end of the file
            if i >= filelen:
                break

            #OpenPGP packet header byte
            self.rawfile.seek(i)
            packet_start = i
            packet_header = ord(self.rawfile.read(1))

            #Bit 7 = packet header (must be 1)
            packet_header_check = (packet_header & 0x80) >> 7
            if packet_header_check != 1:
                raise ValueError("Invalid packet header at byte {} (value=0x{:02x}).".format(i, packet_header))

            #Bit 6 = packet_format
            packet_format = (packet_header & 0x40) >> 6

            #new packet format
            if packet_format == 1:

                #Bits 5-0 = packet tag
                packet_tag = (packet_header & 0x3f)

                #one byte length
                first_octet = ord(self.rawfile.read(1))
                if first_octet < 192:
                    body_len = first_octet

                #two bytes length
                elif first_octet >= 192 and first_octet < 224:
                    second_octet = ord(self.rawfile.read(1))
                    body_len = ((first_octet - 192) << 8) + second_octet + 192

                #five byte length
                elif first_octet == 255:
                    four_bytes = self.rawfile.read(4)
                    body_len = int(four_bytes.encode('hex'), 16)

                #partial length
                #TODO: handle length bytes in the middle of the packet
                else:
                    body_len = 1 << (first_octet & 0x1f)

                    #loop until end of packet is reached
                    original_i = self.rawfile.tell()
                    next_i = original_i + body_len
                    while True:
                        self.rawfile.seek(next_i)
                        next_len = self.rawfile.read(1)
                        first_octet = ord(next_len)
                        if first_octet < 192:
                            body_len += first_octet + 1
                            break
                        elif first_octet >= 192 and first_octet < 224:
                            second_octet = ord(self.rawfile.read(1))
                            body_len += ((first_octet - 192) << 8) + second_octet + 192 + 2
                            break
                        elif first_octet == 255:
                            four_bytes = self.rawfile.read(4)
                            body_len += int(four_bytes.encode('hex'), 16) + 5
                            break
                        else:
                            chunk_len = 1 << (first_octet & 0x1f)
                            body_len += chunk_len + 1
                            next_i += chunk_len + 1
                            if next_i > filelen:
                                body_len = body_len - (next_i - filelen)
                                break
                    self.rawfile.seek(original_i)

            #old packet format
            elif packet_format == 0:

                #Bits 5-2 = packet tag
                packet_tag = (packet_header & 0x3c) >> 2

                #Bits 1-0 = packet length type
                packet_lentype = (packet_header & 0x03)

                #Get packet length based on length type
                if packet_lentype == 0:
                    #one byte length
                    lenbytes = self.rawfile.read(1)
                    body_len = ord(lenbytes)

                elif packet_lentype == 1:
                    #two bytes length
                    lenbytes = self.rawfile.read(2)
                    body_len = int(lenbytes.encode('hex'), 16)

                elif packet_lentype == 2:
                    #four bytes length
                    lenbytes = self.rawfile.read(4)
                    body_len = int(lenbytes.encode('hex'), 16)

                elif packet_lentype == 3:
                    #indeterminate length (i.e. to end of file)
                    self.rawfile.seek(0, os.SEEK_END)
                    body_len = self.rawfile.tell() - i - 1
                    self.rawfile.seek(i + 1)

            #get the packet bytes
            i = self.rawfile.tell()

            #TODO: Public-Key Encrypted Session Key Packet
            if packet_tag == 1:
                raise NotImplementedError("Public-Key Encrypted Session Key Packet is not implemented yet :(")

            #Signature Packet
            elif packet_tag == 2:
                packet_dict = self.read_signature(i, body_len)

            #TODO: Symmetric-Key Encrypted Session Key Packet
            elif packet_tag == 3:
                raise NotImplementedError("Symmetric-Key Encrypted Session Key Packet is not implemented yet :(")

            #One-Pass Signature Packet
            elif packet_tag == 4:
                packet_dict = self.read_onepasssig(i, body_len)

            #TODO: Secret-Key Packet
            elif packet_tag == 5:
                raise NotImplementedError("Secret-Key Packet is not implemented yet :(")

            #Public-Key Packet
            elif packet_tag == 6:
                packet_dict = self.read_pubkey(i, body_len)

            #TODO: Secret-Subkey Packet
            elif packet_tag == 7:
                raise NotImplementedError("Secret-Subkey Packet is not implemented yet :(")

            #Compressed Data Packet
            elif packet_tag == 8:
                packet_dict = self.read_compressed(i, body_len)

            #TODO: Symmetrically Encrypted Data Packet
            elif packet_tag == 9:
                raise NotImplementedError("Symmetrically Encrypted Data Packet is not implemented yet :(")

            #TODO: Marker Packet
            elif packet_tag == 10:
                raise NotImplementedError("Marker Packet is not implemented yet :(")

            #Literal Data Packet
            elif packet_tag == 11:
                packet_dict = self.read_literal(i, body_len)

            #TODO: Trust Packet
            elif packet_tag == 12:
                raise NotImplementedError("Trust Packet is not implemented yet :(")

            #User ID Packet
            elif packet_tag == 13:
                packet_dict = self.read_userid(i, body_len)

            #Public-Subkey Packet
            elif packet_tag == 14:
                packet_dict = self.read_pubsubkey(i, body_len)

            #User Attribute Packet
            elif packet_tag == 17:
                packet_dict = self.read_attribute(i, body_len)

            #TODO: Sym. Encrypted and Integrity Protected Data Packet
            elif packet_tag == 18:
                raise NotImplementedError("Sym. Encrypted and Integrity Protected Data Packet is not implemented yet :(")

            #TODO: Modification Detection Code Packet
            elif packet_tag == 19:
                raise NotImplementedError("Modification Detection Code Packet is not implemented yet :(")

            #TODO: Private or Experimental Values
            elif packet_tag in [60, 61, 62, 63]:
                raise NotImplementedError("Private or Experimental Values are not implemented yet :(")

            #all other packet tags are invalid
            else:
                raise ValueError("Invalid packet tag ({}).".format(packet_tag))

            #add packet format
            packet_len = i + body_len - packet_start
            packet_dict['packet_format'] = packet_format
            packet_dict['packet_start'] = packet_start
            packet_dict['packet_len'] = packet_len
            self.rawfile.seek(packet_start)
            packet_dict['packet_raw'] = self.rawfile.read(packet_len).encode("hex")
            self.append(packet_dict)

            #iterate to the next packet header
            i += body_len

        #return the packets
        return self

    def generate_packets(self):
        bytes = ""
        for i in xrange(0, len(self)):

            #TODO: Public-Key Encrypted Session Key Packet
            if self[i]['tag_id'] == 1:
                raise NotImplementedError("Public-Key Encrypted Session Key Packet is not implemented yet :(")

            #Signature Packet
            elif self[i]['tag_id'] == 2:
                packet_bytes = self.generate_signature(self[i])

            #TODO: Symmetric-Key Encrypted Session Key Packet
            elif self[i]['tag_id'] == 3:
                raise NotImplementedError("Symmetric-Key Encrypted Session Key Packet is not implemented yet :(")

            #TODO: One-Pass Signature Packet
            elif self[i]['tag_id'] == 4:
                raise NotImplementedError("One-Pass Signature Packet is not implemented yet :(")

            #TODO: Secret-Key Packet
            elif self[i]['tag_id'] == 5:
                raise NotImplementedError("Secret-Key Packet is not implemented yet :(")

            #Public-Key Packet
            elif self[i]['tag_id'] == 6:
                packet_bytes = self.generate_pubkey(self[i])

            #TODO: Secret-Subkey Packet
            elif self[i]['tag_id'] == 7:
                raise NotImplementedError("Secret-Subkey Packet is not implemented yet :(")

            #TODO: Compressed Data Packet
            elif self[i]['tag_id'] == 8:
                raise NotImplementedError("Compressed Data Packet is not implemented yet :(")

            #TODO: Symmetrically Encrypted Data Packet
            elif self[i]['tag_id'] == 9:
                raise NotImplementedError("Symmetrically Encrypted Data Packet is not implemented yet :(")

            #TODO: Marker Packet
            elif self[i]['tag_id'] == 10:
                raise NotImplementedError("Marker Packet is not implemented yet :(")

            #TODO: Literal Data Packet
            elif self[i]['tag_id'] == 11:
                raise NotImplementedError("Literal Data Packet is not implemented yet :(")

            #TODO: Trust Packet
            elif self[i]['tag_id'] == 12:
                raise NotImplementedError("Trust Packet is not implemented yet :(")

            #User ID Packet
            elif self[i]['tag_id'] == 13:
                packet_bytes = self.generate_userid(self[i])

            #Public-Subkey Packet
            elif self[i]['tag_id'] == 14:
                packet_bytes = self.generate_pubsubkey(self[i])

            #User Attribute Packet
            elif self[i]['tag_id'] == 17:
                packet_bytes = self.generate_attribute(self[i])

            #TODO: Sym. Encrypted and Integrity Protected Data Packet
            elif self[i]['tag_id'] == 18:
                raise NotImplementedError("Sym. Encrypted and Integrity Protected Data Packet is not implemented yet :(")

            #TODO: Modification Detection Code Packet
            elif self[i]['tag_id'] == 19:
                raise NotImplementedError("Modification Detection Code Packet is not implemented yet :(")

            #TODO: Private or Experimental Values
            elif self[i]['tag_id'] in [60, 61, 62, 63]:
                raise NotImplementedError("Private or Experimental Values are not implemented yet :(")

            #all other packet tags are invalid
            else:
                raise ValueError("Invalid packet tag ({}).".format(self[i]['tag_id']))

            #header bytes
            header = ""
            packet_len = len(packet_bytes)

            #new packet format
            if self[i]['packet_format'] == 1:
                header_byte = 0x80 | 0x40 | self[i]['tag_id']
                header += "{0:0{1}x}".format(header_byte, 2).decode("hex")

                #one byte length
                if packet_len < 192:
                    header += "{0:0{1}x}".format(packet_len, 2).decode("hex")

                #two bytes length
                elif packet_len >= 192 and packet_len <= 8383:
                    octets = (packet_len - 192) | 0xC000
                    header += "{0:0{1}x}".format(octets, 4).decode("hex")

                #five bytes length
                elif packet_len > 8383:
                    header += "ff{0:0{1}x}".format(packet_len, 8).decode("hex")

            #old packet format
            if self[i]['packet_format'] == 0:
                header_byte = 0x80 | 0x00 | (self[i]['tag_id'] << 2)

                #one byte length
                if packet_len < 256:
                    header_byte = header_byte | 0x00
                    header += "{0:0{1}x}".format(header_byte, 2).decode("hex")
                    header += "{0:0{1}x}".format(packet_len, 2).decode("hex")

                #two bytes length
                elif packet_len < 65535:
                    header_byte = header_byte | 0x01
                    header += "{0:0{1}x}".format(header_byte, 2).decode("hex")
                    header += "{0:0{1}x}".format(packet_len, 4).decode("hex")

                #four bytes length
                else:
                    header_byte = header_byte | 0x10
                    header += "{0:0{1}x}".format(header_byte, 2).decode("hex")
                    header += "{0:0{1}x}".format(packet_len, 8).decode("hex")

            bytes += header + packet_bytes

        return bytes

    def armor_to_bytes(self, fileobj):
        """Convert a armored file to non-base64 encoded byte file"""

        #armored message regex pattern
        armor_re = re.compile("\
(?:\
^-----BEGIN PGP SIGNED MESSAGE-----\n\
(?P<clearsign_headers>.*?)\n\n\
(?P<clearsign_text>.*?)\n\
|)\
^-----BEGIN PGP \
(?P<start>\
(?P<key>(?:PUBLIC|PRIVATE) KEY BLOCK)\
|\
(?P<msg>MESSAGE(?: PART (?P<part_i>[0-9]+)(?:\/(?P<part_total>[0-9]+)|)|))\
|\
(?P<sig>SIGNATURE)\
)\
-----\n\
(?P<headers>.*?)\n\n\
(?P<data64>.*?)\n\
(?P<checksum>=[A-Za-z0-9\+\/]{4})\n\
-----END PGP \
(?P<end>\
(?P<key2>(?:PUBLIC|PRIVATE) KEY BLOCK)\
|\
(?P<msg2>MESSAGE(?: PART (?P<part_i2>[0-9]+)(?:\/(?P<part_total2>[0-9]+)|)|))\
|\
(?P<sig2>SIGNATURE)\
)\
-----$", re.MULTILINE|re.DOTALL)

        #adapted from http://stackoverflow.com/a/4544284
        def _crc24(chars):
            INIT = 0xB704CE
            POLY = 0x864CFB
            crc = INIT
            for c in map(ord, chars):
                crc ^= (c << 16)
                for i in xrange(8):
                    crc <<= 1
                    if crc & 0x1000000: crc ^= POLY
            return crc & 0xFFFFFF

        #go through the file and try to find the armored text
        outfile = cStringIO.StringIO()
        fileobj.seek(0)
        file_str = fileobj.read()
        for chunk in armor_re.finditer(file_str):

            #make sure the start and end match
            chunk = chunk.groupdict()
            if chunk['start'] != chunk['end']:
                continue

            #convert the data64 to bytes
            bytes = base64.b64decode(chunk['data64'])

            #test the checksum
            checksum = int(base64.b64decode(chunk['checksum']).encode("hex"), 16)
            checksum_verify = _crc24(bytes)
            if checksum_verify != checksum:
                raise ValueError("Armor checksum ({}) does not match body ({})".format(
                    "{0:0{1}x}".format(checksum, 4),
                    "{0:0{1}x}".format(checksum_verify, 4)))

            #found some armored packets, so add to the output
            outfile.write(bytes)

        #return the file-like object
        outfile.seek(0)
        return outfile

if __name__ == "__main__":
    import sys
    import glob
    import json
    from copy import copy
    from argparse import ArgumentParser
    from argparse import RawTextHelpFormatter

    parser = ArgumentParser(
        formatter_class=RawTextHelpFormatter,
        description="""
Output a pgp file's packets into rows of json-formatted objects.

NOTE: Each row of output is a json object, but the whole output'
itself is not a json list.

Add the --merge-public-keys (-m) to roll up public keys. This is
helpful if you are working with a dumped keyserver database that
is just a huge list of concatenated packets (public keys,
signatures, subkeys, etc.).

Examples:
python openpgp.py /home/me/Alice.pub
python openpgp.py --merge-public-keys "/tmp/dump*.pgp" | gzip > pubkeys.json
""")
    parser.add_argument("file", nargs="+", help="the pgp file(s)")
    parser.add_argument("-m", "--merge-public-keys", action="store_true", help="roll up public key packets")
    args = parser.parse_args()

    #iterate through file list
    for f in args.file:
        paths = glob.glob(os.path.expanduser(f))
        for path in paths:

            #parse the packets
            sys.stderr.write("Parsing {}...".format(path))
            sys.stderr.flush()

            packets = OpenPGPFile(open(path))

            sys.stderr.write("Done\n")
            sys.stderr.flush()

            #merge public keys
            if args.merge_public_keys:

                sys.stderr.write("Dumping public keys...".format(path))
                sys.stderr.flush()

                key = {}
                for p in packets:
                    if p['tag_name'] == "Public-Key":
                        if key:
                            print json.dumps(key, sort_keys=True, encoding="latin1")
                        key = copy(p)
                    else:
                        #bubble errors
                        if p.get("error"):
                            key['error'] = True
                            key.setdefault("error_msg", []).append(p['error_msg'])
                        key.setdefault("packets", []).append(p)
                print json.dumps(key, sort_keys=True, encoding="latin1")

                sys.stderr.write("Done\n")
                sys.stderr.flush()

            #straight dump of packets
            else:

                sys.stderr.write("Dumping packets...".format(path))
                sys.stderr.flush()

                for p in packets:
                    print json.dumps(p, sort_keys=True, encoding="latin1")

                sys.stderr.write("Done\n")
                sys.stderr.flush()

