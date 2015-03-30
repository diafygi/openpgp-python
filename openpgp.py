import os
import sys
import math
import base64
import hashlib

class OpenPGPFile(list):
    """
    A list of parsed packets in an OpenPGP file. I wrote this to have a better
    understanding of the OpenPGP format. It is designed to be very readable,
    use low memory, and use Python's built-in list and dict objects.

    Object format = [
        {
            #standard packet values
            "tag_id": 2,
            "tag_name": "Signature",
            "start": 0,
            "len": 423,

            #packet specific keys (see each read_* method for format)
            ...
        },
        ...
    ]
    """
    rawfile = None

    def __init__(self, fileobj):
        super(list, self).__init__()
        self.rawfile = fileobj
        self.read_packets()

    def read_signature(self, packet_start, packet_len, msg_body=""):
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
            "start": 0,
            "len": 123,

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

            #DSA and ECDSA specific (algo_ids 17, 19)
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
            "start": packet_start,
            "len": packet_len,
        }

        #version
        self.rawfile.seek(packet_start)
        version = ord(self.rawfile.read(1))
        if version not in [3, 4]:
            raise ValueError("Signature version is invalid ({}).".format(version))
        result['version'] = version

        #signature body length (version 3 only)
        if version == 3:
            sig_header_len = ord(self.rawfile.read(1))
            if sig_header_len != 5:
                raise ValueError("Signature body ({} bytes) not 5 bytes long.".format(sig_header_len))

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
                24: "Subkey Binding Signature",
                25: "Primary Key Binding Signature",
                31: "Signature directly on a key",
                32: "Key revocation signature",
                40: "Subkey revocation signature",
                48: "Certification revocation signature",
                64: "Timestamp signature",
                80: "Third-Party Confirmation signature",
            }[signature_type_id]
        except KeyError:
            raise ValueError("Signature type ({}) not recognized.".format(signature_type_id))
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
            }[pubkey_algo_id]
        except KeyError:
            raise ValueError("Public-Key algorithm ({}) not recognized.".format(pubkey_algo_id))
        result['pubkey_algo_id'] = pubkey_algo_id
        result['pubkey_algo_name'] = pubkey_algo_name

        #hash algorithm
        hash_algo_id = ord(self.rawfile.read(1))
        try:
            hash_algo_name = {
                1: "MD5",
                2: "SHA1",
                3: "RIPEMD160",
                8: "SHA256",
                9: "SHA384",
                10: "SHA512",
                11: "SHA224",
            }[hash_algo_id]
        except KeyError:
            raise ValueError("Hash algorithm ({}) not recognized.".format(hash_algo_id))
        result['hash_algo_id'] = hash_algo_id
        result['hash_algo_name'] = hash_algo_name

        #subpackets (version 4 only)
        if version == 4:

            #hashed subpackets length
            hashed_subpacket_len_bytes = self.rawfile.read(2)
            hashed_subpacket_len = int(hashed_subpacket_len_bytes.encode('hex'), 16)
            hashed_subpacket_end = self.rawfile.tell() + hashed_subpacket_len

            #hashed subpackets
            subpackets_raw = []
            while self.rawfile.tell() < hashed_subpacket_end:

                #one byte length
                first_octet = ord(self.rawfile.read(1))
                if first_octet < 192:
                    subpacket_len = first_octet

                #two bytes length
                elif first_octet >= 192 and first_octet <= 223:
                    second_octet = ord(self.rawfile.read(1))
                    subpacket_len = ((first_octet - 192) << 8) + second_octet + 192

                #four bytes length
                elif first_octet == 255:
                    four_bytes = self.rawfile.read(4)
                    subpacket_len = int(four_bytes.encode('hex'), 16)

                #save the position and length of the subpacket
                subpacket_start = self.rawfile.tell()
                self.rawfile.seek(subpacket_start + subpacket_len)
                subpackets_raw.append([True, subpacket_start, subpacket_len])

            #hashed subpackets length
            unhashed_subpacket_len_bytes = self.rawfile.read(2)
            unhashed_subpacket_len = int(unhashed_subpacket_len_bytes.encode('hex'), 16)
            unhashed_subpacket_end = self.rawfile.tell() + unhashed_subpacket_len

            #hashed subpackets
            while self.rawfile.tell() < unhashed_subpacket_end:

                #one byte length
                first_octet = ord(self.rawfile.read(1))
                if first_octet < 192:
                    subpacket_len = first_octet

                #two bytes length
                elif first_octet >= 192 and first_octet <= 223:
                    second_octet = ord(self.rawfile.read(1))
                    subpacket_len = ((first_octet - 192) << 8) + second_octet + 192

                #four bytes length
                elif first_octet == 255:
                    four_bytes = self.rawfile.read(4)
                    subpacket_len = int(four_bytes.encode('hex'), 16)

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
                    }[type_id]
                except KeyError:
                    raise ValueError("Subpacket type ({}) not recognized.".format(type_id))
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
                        raise ValueError("Revoke class must start with a 1 bit.")
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
                        raise ValueError("Revocation code ({}) not recognized.".format(code_id))
                    subpacket['code_id'] = code_id
                    subpacket['code_name'] = code_name

                    #revocation reason
                    reason = self.rawfile.read(subpacket_len - 2)
                    subpacket['reason'] = reason

                #Features (only first bit is defined)
                elif type_id == 30:
                    modification_detection = ord(self.rawfile.read(1)) & 0x80 == 0x80
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
            sig_bytes = self.rawfile.read(sig_numbytes)
            sig_int = int(sig_bytes.encode('hex'), 16)
            if sig_int >> sig_len != 0:
                raise ValueError("RSA signature has non-zero leading bits.")
            sig_hex = "{0:x}".format(sig_int)
            if len(sig_hex) % 2:
                sig_hex = "0{}".format(sig_hex)
            result['signature'] = sig_hex

        #DSA signature
        elif pubkey_algo_id in [1, 3]:

            #DSA value r
            r_len_bytes = self.rawfile.read(2)
            r_len = int(r_len_bytes.encode('hex'), 16)
            r_numbytes = int(math.ceil(r_len / 8.0))
            r_bytes = self.rawfile.read(r_numbytes)
            r_int = int(r_bytes.encode('hex'), 16)
            if r_int >> r_len != 0:
                raise ValueError("DSA signature r has non-zero leading bits.")
            r_hex = "{0:x}".format(r_int)
            if len(r_hex) % 2:
                r_hex = "0{}".format(r_hex)
            result['signature_r'] = r_hex

            #DSA value s
            s_len_bytes = self.rawfile.read(2)
            s_len = int(s_len_bytes.encode('hex'), 16)
            s_numbytes = int(math.ceil(s_len / 8.0))
            s_bytes = self.rawfile.read(s_numbytes)
            s_int = int(s_bytes.encode('hex'), 16)
            if s_int >> s_len != 0:
                raise ValueError("DSA signature s has non-zero leading bits.")
            s_hex = "{0:x}".format(s_int)
            if len(s_hex) % 2:
                s_hex = "0{}".format(s_hex)
            result['signature_r'] = s_hex

        #binary data document data
        if signature_type_name == "Signature of a binary document":
            #find the closest data packet
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Literal Data":
                    self.rawfile.seek(self[i]['start'])
                    msg_body = self.rawfile.read(self[i]['len'])
                    break
                i = i - 1

        #text data document data
        elif signature_type_name == "Signature of a canonical text document":
            #find the closest data packet
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Literal Data":
                    self.rawfile.seek(self[i]['start'])
                    msg_body = self.rawfile.read(self[i]['len'])
                    break
                i = i - 1
            #convert linebreaks to \r\n
            if "\r" not in msg_body:
                msg_body = msg_body.replace("\n", "\r\n")

        #user id/attribute document data
        elif signature_type_name in [
            "Generic certification",
            "Persona certification",
            "Casual certification",
            "Positive certification",
        ]:
            #find the closest primary public key
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Key":
                    self.rawfile.seek(self[i]['start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['len'], 4).decode("hex")
                    msg_body = prefix + len_octets + self.rawfile.read(self[i]['len'])
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
                        len_octets = "{0:0{1}x}".format(self[i]['len'], 8).decode("hex")

                    self.rawfile.seek(self[i]['start'])
                    msg_body += prefix + len_octets + self.rawfile.read(self[i]['len'])
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
                        len_octets = "{0:0{1}x}".format(self[i]['len'], 8).decode("hex")

                    self.rawfile.seek(self[i]['start'])
                    msg_body += prefix + len_octets + self.rawfile.read(self[i]['len'])
                    break

                i = i - 1

        #subkey binding document data
        elif signature_type_name in [
            "Subkey Binding Signature",
            "Primary Key Binding Signature",
        ]:

            #find the closest primary public key
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Key":
                    self.rawfile.seek(self[i]['start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['len'], 4).decode("hex")
                    msg_body = prefix + len_octets + self.rawfile.read(self[i]['len'])
                    break
                i = i - 1

            #find the closest subkey
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Subkey":
                    self.rawfile.seek(self[i]['start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['len'], 4).decode("hex")
                    msg_body += prefix + len_octets + self.rawfile.read(self[i]['len'])
                    break
                i = i - 1

        #primary key revoking document data
        elif signature_type_name == "Key revocation signature":

            #find the closest primary public key
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Key":
                    self.rawfile.seek(self[i]['start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['len'], 4).decode("hex")
                    msg_body = prefix + len_octets + self.rawfile.read(self[i]['len'])
                    break
                i = i - 1

        #subkey revoking document data
        elif signature_type_name == "Subkey revocation signature":

            #find the closest primary public key
            i = len(self) - 1
            while i >= 0:
                if self[i]['tag_name'] == "Public-Subkey":
                    self.rawfile.seek(self[i]['start'])
                    prefix = "\x99"
                    len_octets = "{0:0{1}x}".format(self[i]['len'], 4).decode("hex")
                    msg_body = prefix + len_octets + self.rawfile.read(self[i]['len'])
                    break
                i = i - 1

        #hash trailer
        if version == 3:
            self.rawfile.seek(packet_start + 1)
            trailer = self.rawfile.read(5).encode("hex")
        elif version == 4:
            hash_len = hashed_subpacket_end - packet_start
            self.rawfile.seek(packet_start)
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
        h.update(data)
        result['hash'] = h.hexdigest()

        #validate hash_check
        if not result['hash'].startswith(hash_check):
            raise ValueError("Digest doesn't start with '{}'.".format(hash_check))

        return result

    def read_pubkey(self, packet_start, packet_len):
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
            "start": 0,
            "len": 123,

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
            "start": packet_start,
            "len": packet_len,
        }

        #version
        self.rawfile.seek(packet_start)
        version = ord(self.rawfile.read(1))
        if version not in [3, 4]:
            raise ValueError("Public Key version is invalid ({}).".format(version))
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
            }[algo_id]
        except KeyError:
            raise ValueError("Public-Key algorithm ({}) not recognized.".format(algo_id))
        if version == 3 and algo_id not in [1, 2, 3]:
            raise ValueError("Public Key algorithm ({}) is not RSA, which is required for Version 3 public keys.".format(algo_id))
        result['algo_id'] = algo_id
        result['algo_name'] = algo_name

        #RSA
        if algo_id in [1, 2, 3]:

            #modulus
            n_len_bytes = self.rawfile.read(2)
            n_len = int(n_len_bytes.encode('hex'), 16)
            n_numbytes = int(math.ceil(n_len / 8.0))
            n_bytes = self.rawfile.read(n_numbytes)
            n_int = int(n_bytes.encode('hex'), 16)
            if n_int >> n_len != 0:
                raise ValueError("RSA modulus has non-zero leading bits.")
            n_hex = "{0:x}".format(n_int)
            if len(n_hex) % 2:
                n_hex = "0{}".format(n_hex)
            result['n'] = n_hex
            pem = "0282{0:0{1}x}00".format(n_numbytes + 1, 4) + n_hex

            #exponent
            e_len_bytes = self.rawfile.read(2)
            e_len = int(e_len_bytes.encode('hex'), 16)
            e_numbytes = int(math.ceil(e_len / 8.0))
            e_bytes = self.rawfile.read(e_numbytes)
            e_int = int(e_bytes.encode('hex'), 16)
            if e_int >> e_len != 0:
                raise ValueError("RSA exponent has non-zero leading bits.")
            e_hex = "{0:x}".format(e_int)
            if len(e_hex) % 2:
                e_hex = "0{}".format(e_hex)
            result['e'] = e_hex
            pem += "02{0:0{1}x}".format(e_numbytes, 2) + e_hex

            #pem format
            pem_seq = "3082{0:0{1}x}".format(len(pem) / 2, 4) + pem
            pem_bitseq = "0382{0:0{1}x}00".format(len(pem_seq) / 2 + 1, 4) + pem_seq
            pem_rsa = "300d06092a864886f70d0101010500" + pem_bitseq
            pem_full = "3082{0:0{1}x}".format(len(pem_rsa) / 2, 4) + pem_rsa
            pem_bytes = pem_full.decode("hex")

        #Elgamal
        elif algo_id in [16, 20]:
            raise NotImplementedError("Elgamal public key parsing is not implemented yet :(")

        #DSA
        elif algo_id == 17:
            raise NotImplementedError("DSA public key parsing is not implemented yet :(")

        #ECDH
        elif algo_id == 18:
            raise NotImplementedError("ECDH public key parsing is not implemented yet :(")

        #ECDSA
        elif algo_id == 19:
            raise NotImplementedError("ECDSA public key parsing is not implemented yet :(")

        #DH
        elif algo_id == 21:
            raise NotImplementedError("DH public key parsing is not implemented yet :(")

        #reject all other algorithms
        else:
            raise ValueError("Public Key algorithm is invalid ({}).".format(algo_id))

        #pem file
        p = base64.b64encode(pem_bytes)
        pem_b64 = "\n".join([p[i*64:(i+1)*64] for i in xrange(0, int(math.ceil(len(p)/64))+1)])
        pem_str = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----".format(pem_b64)
        result['pem'] = pem_str

        #fingerprint (version 3)
        if version == 3:
            body = "{}{}".format(n_bytes, e_bytes)
            result['fingerprint'] = hashlib.md5(body).hexdigest()
            result['key_id'] = result['n'][-16:]

        #fingerprint (version 4)
        elif version == 4:
            self.rawfile.seek(packet_start)
            len_hex = "{0:0{1}x}".format(packet_len, 4).decode("hex")
            body = "\x99{}{}".format(len_hex, self.rawfile.read(packet_len))
            result['fingerprint'] = hashlib.sha1(body).hexdigest()
            result['key_id'] = result['fingerprint'][-16:]

        return result

    def read_userid(self, packet_start, packet_len):
        """
        Specification:
        https://tools.ietf.org/html/rfc4880#section-5.11

        Return Format:
        {
            "tag_id": 6,
            "tag_name": "User ID",
            "start": 0,
            "len": 123,
            "user_id": "John Doe (johndoe1234) <john.doe@example.com>",
        }
        """
        self.rawfile.seek(packet_start)
        return {
            "tag_id": 13,
            "tag_name": "User ID",
            "start": packet_start,
            "len": packet_len,
            "user_id": self.rawfile.read(packet_len),
        }

    def read_pubsubkey(self, packet_start, packet_len):
        """
        Specification:
        https://tools.ietf.org/html/rfc4880#section-5.5.1.2

        Return Format:
        Same as read_pubkey, except tag_id is 14 and tag_name is "Public-Subkey"
        """
        pubkey_result = self.read_pubkey(packet_start, packet_len)
        pubkey_result['tag_id'] = 14
        pubkey_result['tag_name'] = "Public-Subkey"
        return pubkey_result

    def packetize(self, packet_tag, packet_start, packet_len):
        """
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
        60 to 63 -- Private or Experimental Values"""

        #TODO: Public-Key Encrypted Session Key Packet
        if packet_tag == 1:
            raise NotImplementedError("Public-Key Encrypted Session Key Packet is not implemented yet :(")

        #Signature Packet
        elif packet_tag == 2:
            return self.read_signature(packet_start, packet_len)

        #TODO: Symmetric-Key Encrypted Session Key Packet
        elif packet_tag == 3:
            raise NotImplementedError("Symmetric-Key Encrypted Session Key Packet is not implemented yet :(")

        #TODO: One-Pass Signature Packet
        elif packet_tag == 4:
            raise NotImplementedError("One-Pass Signature Packet is not implemented yet :(")

        #TODO: Secret-Key Packet
        elif packet_tag == 5:
            raise NotImplementedError("Secret-Key Packet is not implemented yet :(")

        #Public-Key Packet
        elif packet_tag == 6:
            return self.read_pubkey(packet_start, packet_len)

        #TODO: Secret-Subkey Packet
        elif packet_tag == 7:
            raise NotImplementedError("Secret-Subkey Packet is not implemented yet :(")

        #TODO: Compressed Data Packet
        elif packet_tag == 8:
            raise NotImplementedError("Compressed Data Packet is not implemented yet :(")

        #TODO: Symmetrically Encrypted Data Packet
        elif packet_tag == 9:
            raise NotImplementedError("Symmetrically Encrypted Data Packet is not implemented yet :(")

        #TODO: Marker Packet
        elif packet_tag == 10:
            raise NotImplementedError("Marker Packet is not implemented yet :(")

        #TODO: Literal Data Packet
        elif packet_tag == 11:
            raise NotImplementedError("Literal Data Packet is not implemented yet :(")

        #TODO: Trust Packet
        elif packet_tag == 12:
            raise NotImplementedError("Trust Packet is not implemented yet :(")

        #User ID Packet
        elif packet_tag == 13:
            return self.read_userid(packet_start, packet_len)

        #Public-Subkey Packet
        elif packet_tag == 14:
            return self.read_pubsubkey(packet_start, packet_len)

        #TODO: User Attribute Packet
        elif packet_tag == 17:
            raise NotImplementedError("User Attribute Packet is not implemented yet :(")

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


    def read_packets(self):
        """https://tools.ietf.org/html/rfc4880#section-4.2"""

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
                    packet_len = first_octet

                #two bytes length
                elif first_octet >= 192 and first_octet <= 223:
                    second_octet = ord(self.rawfile.read(1))
                    packet_len = ((first_octet - 192) << 8) + second_octet + 192

                #four bytes length
                elif first_octet == 255:
                    four_bytes = self.rawfile.read(4)
                    packet_len = int(four_bytes.encode('hex'), 16)

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
                    packet_len = ord(lenbytes)

                elif packet_lentype == 1:
                    #two bytes length
                    lenbytes = self.rawfile.read(2)
                    packet_len = int(lenbytes.encode('hex'), 16)

                elif packet_lentype == 2:
                    #four bytes length
                    lenbytes = self.rawfile.read(4)
                    packet_len = int(lenbytes.encode('hex'), 16)

                elif packet_lentype == 3:
                    #indeterminate length (i.e. to end of file)
                    self.rawfile.seek(0, os.SEEK_END)
                    packet_len = self.rawfile.tell() - i - 1
                    self.rawfile.seek(i + 1)

            #get the packet bytes
            i = self.rawfile.tell()
            parsed_packet = self.packetize(packet_tag, i, packet_len)
            self.append(parsed_packet)

            #iterate to the next packet header
            i += packet_len

        #return the packets
        return self

if __name__ == "__main__":
    import json
    print json.dumps(OpenPGPFile(open(sys.argv[1])), indent=4, sort_keys=True)

