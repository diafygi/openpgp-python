import os
import sys
import json
import glob
import gzip
from datetime import datetime
from django.core.management.base import BaseCommand
from django.utils.timezone import make_aware
from keys import models

class Command(BaseCommand):
    help = "Import json public keys into the database."

    def add_arguments(self, parser):
        parser.add_argument("file", nargs="+")

    def handle(self, *args, **options):
        for filename in options['file']:
            paths = glob.glob(os.path.expanduser(filename))
            for path in paths:
                if path.endswith(".gz"):
                    f = gzip.GzipFile(path)
                else:
                    f = open(path)

                count_new = 0
                count_updated = 0
                for i, line in enumerate(f):
                    key = json.loads(line)

                    #try to find existing key
                    key_obj = None
                    matching_keys = models.PublicKey.objects.filter(
                        long_keyid=key.get("key_id", None))
                    for k in matching_keys:
                        if json.loads(k.json)['packet_raw'] == key['packet_raw']:
                            key_obj = k
                            count_updated += 1
                            break

                    #create new key if couldn't find an existing one
                    if key_obj is None:
                        count_new += 1
                        key_json = dict((k, v) for k, v in key.items() if k != "packets")
                        key_obj = models.PublicKey(json=json.dumps(key_json, sort_keys=True, indent=4))


                    #update the public key attributes
                    key_obj.errors = json.dumps(key['error_msg'], sort_keys=True, indent=4) if key.get("error_msg", None) is not None else None
                    key_obj.short_keyid = key['key_id'][-8:] if key.get("key_id", None) is not None else None
                    key_obj.long_keyid = key['key_id'] if key.get("key_id", None) is not None else None
                    key_obj.fingerprint = key['fingerprint'] if key.get("fingerprint", None) is not None else None
                    key_obj.created = make_aware(datetime.utcfromtimestamp(key['creation_time'])) if key.get("creation_time", None) is not None else None
                    key_obj.algo_id = key['algo_id'] if key.get("algo_id", None) is not None else None
                    key_obj.save()

                    #got through the packets and insert as needed
                    signature_target = key_obj
                    for packet in key.get("packets", []):

                        #SubKey
                        if packet['tag_id'] == 14:

                            #try to find existing user_id
                            subkey_obj = None
                            matching_subkeys = models.SubKey.objects.filter(publickey=key_obj)
                            for u in matching_subkeys:
                                if json.loads(u.json)['packet_raw'] == packet['packet_raw']:
                                    subkey_obj = u
                                    break

                            #create new SubKey if couldn't find an existing one
                            if subkey_obj is None:
                                subkey_obj = models.SubKey(json=json.dumps(packet, sort_keys=True, indent=4), publickey=key_obj)

                            #update the SubKey attributes
                            subkey_obj.errors = json.dumps(packet['error_msg'], sort_keys=True, indent=4) if packet.get("error_msg", None) is not None else None
                            subkey_obj.short_keyid = packet['key_id'][-8:] if packet.get("key_id", None) is not None else None
                            subkey_obj.long_keyid = packet['key_id'] if packet.get("key_id", None) is not None else None
                            subkey_obj.fingerprint = packet['fingerprint'] if packet.get("fingerprint", None) is not None else None
                            subkey_obj.created = make_aware(datetime.utcfromtimestamp(packet['creation_time'])) if packet.get("creation_time", None) is not None else None
                            subkey_obj.algo_id = packet['algo_id'] if packet.get("algo_id", None) is not None else None
                            subkey_obj.save()

                            signature_target = subkey_obj

                        #UserID
                        elif packet['tag_id'] == 13:

                            #try to find existing user_id
                            userid_obj = None
                            matching_userids = models.UserID.objects.filter(publickey=key_obj)
                            for u in matching_userids:
                                if json.loads(u.json)['packet_raw'] == packet['packet_raw']:
                                    userid_obj = u
                                    break

                            #create new UserID if couldn't find an existing one
                            if userid_obj is None:
                                userid_obj = models.UserID(json=json.dumps(packet, sort_keys=True, indent=4), publickey=key_obj)

                            #update the UserID attributes
                            userid_obj.errors = json.dumps(packet['error_msg'], sort_keys=True, indent=4) if packet.get("error_msg", None) is not None else None
                            userid_obj.text = packet['user_id'] if packet.get("user_id", None) is not None else None
                            userid_obj.save()

                            signature_target = userid_obj

                        #UserAttribute
                        elif packet['tag_id'] == 17:

                            #try to find existing user_attribute
                            useratt_obj = None
                            matching_useratts = models.UserAttribute.objects.filter(publickey=key_obj)
                            for u in matching_useratts:
                                if json.loads(u.json)['packet_raw'] == packet['packet_raw']:
                                    useratt_obj = u
                                    break

                            #create new UserAttribute if couldn't find an existing one
                            if useratt_obj is None:
                                useratt_obj = models.UserAttribute(json=json.dumps(packet, sort_keys=True, indent=4), publickey=key_obj)

                            #update the UserAttribute attributes
                            useratt_obj.errors = json.dumps(packet['error_msg'], sort_keys=True, indent=4) if packet.get("error_msg", None) is not None else None
                            useratt_obj.save()

                            signature_target = useratt_obj

                            #update the images for the user attribute
                            for img in packet['subpackets']:

                                #find any existing images
                                image_obj = None
                                matching_images = models.Image.objects.filter(userattribute=useratt_obj)
                                for jpg in matching_images:
                                    if jpg.image == img.get("image", None):
                                        image_obj = jpg
                                        break

                                #create new Image if couldn't find an existing one
                                if image_obj is None:
                                    image_obj = models.Image.objects.create(
                                        userattribute=useratt_obj,
                                        encoding=img.get("encoding", None),
                                        image=img.get("image", None),
                                    )

                        #Signature
                        elif packet['tag_id'] == 2:

                            #try to find existing signature
                            sig_obj = None
                            matching_sigs = models.Signature.objects.filter(publickey=key_obj)
                            for s in matching_sigs:
                                if json.loads(s.json)['packet_raw'] == packet['packet_raw']:
                                    sig_obj = s
                                    break

                            #create new Signature if couldn't find an existing one
                            if sig_obj is None:
                                sig_obj = models.Signature(json=json.dumps(packet, sort_keys=True, indent=4), publickey=key_obj)

                            #update the Signature attributes
                            sig_obj.errors = json.dumps(packet['error_msg'], sort_keys=True, indent=4) if packet.get("error_msg", None) is not None else None
                            sig_obj.subkey = signature_target if isinstance(signature_target, models.SubKey) else None
                            sig_obj.userid = signature_target if isinstance(signature_target, models.UserID) else None
                            sig_obj.userattribute = signature_target if isinstance(signature_target, models.UserAttribute) else None
                            sig_obj.signature_type = packet['signature_type_id'] if packet.get("signature_type_id", None) is not None else None
                            sig_obj.pubkey_algo_id = packet['pubkey_algo_id'] if packet.get("pubkey_algo_id", None) is not None else None
                            sig_obj.hash_algo_id = packet['hash_algo_id'] if packet.get("hash_algo_id", None) is not None else None
                            sig_obj.subpackets = json.dumps(packet['subpackets'], sort_keys=True, indent=4) if packet.get("subpackets", None) is not None else None

                            #find created time and signer key_id (version 3)
                            if packet.get("creation_time", None) is not None:
                                sig_obj.created = make_aware(datetime.utcfromtimestamp(packet['creation_time']))
                            if packet.get("key_id", None) is not None:
                                sig_obj.signer_hex = packet['key_id']

                            #find created time and signer key_id (version 4)
                            for sp in packet.get("subpackets", []):
                                if sp['type_id'] == 2 and sp.get("creation_time", None) is not None:
                                    sig_obj.created = make_aware(datetime.utcfromtimestamp(sp['creation_time']))
                                elif sp['type_id'] == 16 and sp.get("key_id", None) is not None:
                                    sig_obj.signer_hex = sp['key_id']

                            sig_obj.save()

                            #mark as self-signature
                            if sig_obj.signer_hex is not None:
                                sig_obj.is_selfsig = sig_obj.signer_hex == key_obj.long_keyid
                                if sig_obj.is_selfsig:
                                    sig_obj.signer = key_obj
                                sig_obj.save()


                    #print a status update
                    if i % 100 == 99:
                        print "Saved {} public keys ({} new, {} updated) from {}...".format(
                            i+1, count_new, count_updated, path)

                print "Done! Saved {} keys ({} new, {} updated) from {}!".format(
                    i+1, count_new, count_updated, path)





