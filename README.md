# openpgp-python

### Description

This is OpenPGP file parser written in python. It will dump the packet contents
of a PGP/GPG formatted file to a series of json-formatted objects. These json
objects are much easier to explore and import into various data analysis tools
and databases.

### How to use

#### Command Line

#### Python Class

### Output formats

#### Public-Key and Public-Subkey Packets
#### Signature Packets
#### User ID Packets
#### User Attribute Packets

### Roadmap

* ~~Parsing raw packets.~~
* Parsing [ASCII armored packets](https://tools.ietf.org/html/rfc4880#section-6.2).
* ~~Parsing publickey related packets.~~
  * ~~[Signature Packet (Tag 2)](https://tools.ietf.org/html/rfc4880#section-5.2)~~
  * ~~[Public-Key Packet (Tag 6)](https://tools.ietf.org/html/rfc4880#section-5.5.1.1)~~
  * ~~[Public-Subkey Packet (Tag 14)](https://tools.ietf.org/html/rfc4880#section-5.5.1.2)~~
  * ~~[User ID Packet (Tag 13)](https://tools.ietf.org/html/rfc4880#section-5.11)~~
  * ~~[User Attribute Packet (Tag 17)](https://tools.ietf.org/html/rfc4880#section-5.12)~~
* Parsing non-publickey related packets.
  * [Public-Key Encrypted Session Key Packets (Tag 1)](https://tools.ietf.org/html/rfc4880#section-5.1)
  * [Symmetric-Key Encrypted Session Key Packets (Tag 3)](https://tools.ietf.org/html/rfc4880#section-5.3)
  * [One-Pass Signature Packets (Tag 4)](https://tools.ietf.org/html/rfc4880#section-5.4)
  * [Secret-Key Packet (Tag 5)](https://tools.ietf.org/html/rfc4880#section-5.5.1.3)
  * [Secret-Subkey Packet (Tag 7)](https://tools.ietf.org/html/rfc4880#section-5.5.1.4)
  * [Compressed Data Packet (Tag 8)](https://tools.ietf.org/html/rfc4880#section-5.6)
  * [Symmetrically Encrypted Data Packet (Tag 9)](https://tools.ietf.org/html/rfc4880#section-5.7)
  * [Marker Packet (Obsolete Literal Packet) (Tag 10)](https://tools.ietf.org/html/rfc4880#section-5.8)
  * [Literal Data Packet (Tag 11)](https://tools.ietf.org/html/rfc4880#section-5.9)
  * [Trust Packet (Tag 12)](https://tools.ietf.org/html/rfc4880#section-5.10)
  * [Sym. Encrypted Integrity Protected Data Packet (Tag 18)](https://tools.ietf.org/html/rfc4880#section-5.13)
  * [Modification Detection Code Packet (Tag 19)](https://tools.ietf.org/html/rfc4880#section-5.14)

