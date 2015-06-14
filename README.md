# openpgp-python

### Description

This is OpenPGP file parser written in python. It will dump the packet contents
of a PGP/GPG formatted file to a series of json-formatted objects. These json
objects are much easier to explore and import into various data analysis tools
and databases. This library is able to parse the entire sks-keyserver pool of
public keys.

### Table of contents

* [How to use](#how-to-use)
  * [Command line](#command-line)
  * [Python library](#python-library)
* [Output formats](#output-formats)
  * [Public-Key and Public-Subkey Packets](#public-key-and-public-subkey-packets)
  * [Signature Packets](#signature-packets)
  * [User ID Packets](#user-id-packets)
  * [User Attribute Packets](#user-attribute-packets)
* [Roadmap](#roadmap)
* [Keyserver dump](#keyserver-dump)
* [Contributing](#contributing)

### How to use

#### Command line

```
$ python openpgp.py --help
usage: openpgp.py [-h] [-m] file [file ...]

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

positional arguments:
  file                  the pgp file(s)

optional arguments:
  -h, --help            show this help message and exit
  -m, --merge-public-keys
                        roll up public key packets
```

#### Python library

```
$ gpg --recv-key A5452207
$ gpg --export A5452207 > /tmp/Alice.pub.gpg
$ python
Python 2.7.6 (default, Mar 22 2014, 22:59:56)
[GCC 4.8.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from openpgp import OpenPGPFile
>>> f = open("/tmp/Alice.pub.gpg")
>>> packets = OpenPGPFile(f)
>>> print [p['tag_name'] for p in packets]
['Public-Key', 'User ID', 'Signature', 'Signature', 'Signature', 'Public-Subkey', 'Signature']
```

### Output formats

NOTE: These formats are the raw python dictionary formats. When using the
command line, these are converted to json.

#### Public-Key and Public-Subkey Packets

```python
{
    #standard packet values
    "packet_format": 0 or 1,
    "packet_start": 0,
    "packet_raw": "deadbeefdeadbeefdeadbeef...",
    "tag_id": 6, #14 if subkey
    "tag_name": "Public-Key", #"Public-Subkey" if subkey
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

    #packets (if the -m flag was passed in the command line)
    "packets": [...], #list of rolled up public key packets
}
```

#### Signature Packets

```python
{
    #standard packet values
    "packet_format": 0 or 1,
    "packet_start": 0,
    "packet_raw": "deadbeefdeadbeefdeadbeef...",
    "tag_id": 2,
    "tag_name": "Signature",
    "body_start": 5,
    "body_len": 423,

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

```

#### User ID Packets

```python
{
    #standard packet values
    "packet_format": 0 or 1,
    "packet_start": 0,
    "packet_raw": "deadbeefdeadbeefdeadbeef...",
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
```

#### User Attribute Packets

```python
{
    #standard packet values
    "packet_format": 0 or 1,
    "packet_start": 0,
    "packet_raw": "deadbeefdeadbeefdeadbeef...",
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
```

### Roadmap

* ~~Parsing raw packets.~~
* ~~Parsing [ASCII armored packets](https://tools.ietf.org/html/rfc4880#section-6.2)~~
* ~~Parsing publickey related packets.~~
  * ~~[Signature Packet (Tag 2)](https://tools.ietf.org/html/rfc4880#section-5.2)~~
  * ~~[Public-Key Packet (Tag 6)](https://tools.ietf.org/html/rfc4880#section-5.5.1.1)~~
    * ~~RSA~~
    * ~~Elgamal~~
    * ~~DSA~~
    * ~~ECDH~~
    * ~~ECDSA~~
    * DH
    * ~~EdDSA~~
  * ~~[Public-Subkey Packet (Tag 14)](https://tools.ietf.org/html/rfc4880#section-5.5.1.2)~~
  * ~~[User ID Packet (Tag 13)](https://tools.ietf.org/html/rfc4880#section-5.11)~~
  * ~~[User Attribute Packet (Tag 17)](https://tools.ietf.org/html/rfc4880#section-5.12)~~
* Parsing non-publickey related packets.
  * [Public-Key Encrypted Session Key Packets (Tag 1)](https://tools.ietf.org/html/rfc4880#section-5.1)
  * [Symmetric-Key Encrypted Session Key Packets (Tag 3)](https://tools.ietf.org/html/rfc4880#section-5.3)
  * ~~[One-Pass Signature Packets (Tag 4)](https://tools.ietf.org/html/rfc4880#section-5.4)~~
  * [Secret-Key Packet (Tag 5)](https://tools.ietf.org/html/rfc4880#section-5.5.1.3)
  * [Secret-Subkey Packet (Tag 7)](https://tools.ietf.org/html/rfc4880#section-5.5.1.4)
  * ~~[Compressed Data Packet (Tag 8)](https://tools.ietf.org/html/rfc4880#section-5.6)~~
  * [Symmetrically Encrypted Data Packet (Tag 9)](https://tools.ietf.org/html/rfc4880#section-5.7)
  * [Marker Packet (Obsolete Literal Packet) (Tag 10)](https://tools.ietf.org/html/rfc4880#section-5.8)
  * ~~[Literal Data Packet (Tag 11)](https://tools.ietf.org/html/rfc4880#section-5.9)~~
  * [Trust Packet (Tag 12)](https://tools.ietf.org/html/rfc4880#section-5.10)
  * [Sym. Encrypted Integrity Protected Data Packet (Tag 18)](https://tools.ietf.org/html/rfc4880#section-5.13)
  * [Modification Detection Code Packet (Tag 19)](https://tools.ietf.org/html/rfc4880#section-5.14)
* Generating raw packets
  * [Public-Key Encrypted Session Key Packets (Tag 1)](https://tools.ietf.org/html/rfc4880#section-5.1)
  * ~~[Signature Packet (Tag 2)](https://tools.ietf.org/html/rfc4880#section-5.2)~~
  * [Symmetric-Key Encrypted Session Key Packets (Tag 3)](https://tools.ietf.org/html/rfc4880#section-5.3)
  * [One-Pass Signature Packets (Tag 4)](https://tools.ietf.org/html/rfc4880#section-5.4)
  * [Secret-Key Packet (Tag 5)](https://tools.ietf.org/html/rfc4880#section-5.5.1.3)
  * [Public-Key Packet (Tag 6)](https://tools.ietf.org/html/rfc4880#section-5.5.1.1)
    * ~~RSA~~
    * Elgamal
    * DSA
    * ECDH
    * ECDSA
    * DH
    * EdDSA
  * [Secret-Subkey Packet (Tag 7)](https://tools.ietf.org/html/rfc4880#section-5.5.1.4)
  * [Compressed Data Packet (Tag 8)](https://tools.ietf.org/html/rfc4880#section-5.6)
  * [Symmetrically Encrypted Data Packet (Tag 9)](https://tools.ietf.org/html/rfc4880#section-5.7)
  * [Marker Packet (Obsolete Literal Packet) (Tag 10)](https://tools.ietf.org/html/rfc4880#section-5.8)
  * [Literal Data Packet (Tag 11)](https://tools.ietf.org/html/rfc4880#section-5.9)
  * [Trust Packet (Tag 12)](https://tools.ietf.org/html/rfc4880#section-5.10)
  * ~~[User ID Packet (Tag 13)](https://tools.ietf.org/html/rfc4880#section-5.11)~~
  * ~~[Public-Subkey Packet (Tag 14)](https://tools.ietf.org/html/rfc4880#section-5.5.1.2)~~
  * ~~[User Attribute Packet (Tag 17)](https://tools.ietf.org/html/rfc4880#section-5.12)~~
  * [Sym. Encrypted Integrity Protected Data Packet (Tag 18)](https://tools.ietf.org/html/rfc4880#section-5.13)
  * [Modification Detection Code Packet (Tag 19)](https://tools.ietf.org/html/rfc4880#section-5.14)
* Generating ASCII armored packets
* Tests

#### Keyserver dump

This is how you can load a keyserver dump into elasticsearch.

```sh
#download openpgp.py
mkdir ~/opengpg-python
cd ~/openpgp-python
wget https://raw.githubusercontent.com/diafygi/openpgp-python/master/openpgp.py > openpgp.py

#download the latest keyserver dump
mkdir ~/dump
cd ~/dump
wget -c -r -p -e robots=off --timestamping --level=1 --cut-dirs=3 \
--no-host-directories http://keyserver.mattrude.com/dump/current/

#Parse keyserver dump to json gzip files (split every 1000 lines)
ls -1 ~/dump/*.pgp | \
xargs -I % sh -c "python ~/openpgp-python/openpgp.py --merge-public-keys '%' | \
split -l 1000 -d --filter 'gzip -9 > $FILE.gz' - '%.json.'"

#Bulk index each gzip file into elasticsearch
ls -1 ~/dump/*.json.*.gz | \
xargs -I % sh -c "zcat '%' | \
sed '0~1 s/^/{ \"index\" : { \"_index\" : \"keyserver1\", \"_type\" : \"key\" } }\n/' | \
curl -X POST --data-binary @- http://localhost:9200/_bulk | \
{ cat -; echo ''; } >> ~/results.log"
```

### Contributing

I'd love pull requests adding support for unsupported packets types. I'd also
love pull requests adding tests. File bug reports and feature requests in the
issue tracker. Thanks!

