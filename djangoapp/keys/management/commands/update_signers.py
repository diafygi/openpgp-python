from django.core.management.base import BaseCommand
from keys import models

class Command(BaseCommand):
    help = "Update signer foreign keys in database."

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        count_updated = 0
        count_skipped = 0
        for i, sig in enumerate(models.Signature.objects.filter(signer=None).iterator()):

            #skip signatures with missing signers
            if sig.signer_hex is None:
                count_skipped += 1
                continue

            #find matching key_ids
            matching_keyids = list(models.PublicKey.objects.filter(long_keyid=sig.signer_hex))
            matching_keyids.extend(list(models.SubKey.objects.select_related("publickey").filter(long_keyid=sig.signer_hex)))

            #update the signer
            if len(matching_keyids) > 0:
                for k in matching_keyids:
                    #TODO verify signatures
                    sig.signer = k.publickey if isinstance(k, models.SubKey) else k
                count_updated += 1
                sig.save()

            #print a status update
            if i % 100 == 99:
                print "Parsed {} signatures ({} updated, {} skipped)...".format(
                    i+1, count_updated, count_skipped)

        print "Done! Parsed {} signatures ({} updated, {} skipped)!".format(
            i+1, count_updated, count_skipped)




