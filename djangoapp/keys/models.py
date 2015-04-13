from django.db import models
from keys import algos

class PublicKey(models.Model):
    json = models.TextField()
    errors = models.TextField(blank=True, null=True)
    short_keyid = models.CharField(max_length=8, blank=True, null=True)
    long_keyid = models.CharField(max_length=16, blank=True, null=True, db_index=True)
    fingerprint = models.CharField(max_length=40, blank=True, null=True)
    created = models.DateTimeField(blank=True, null=True)
    algo_id = models.IntegerField(blank=True, null=True)

    class Meta:
        verbose_name_plural = "      Public Keys"

    @property
    def algo(self):
        return algos.PUBLICKEY_ALGORITHMS.get(self.algo_id,
            "Unknown algorithm ({})".format(self.algo_id))

    def __unicode__(self):
        return u"PublicKey (id={}, keyid={}, algo={})".format(self.pk, self.short_keyid, self.algo)

class SubKey(models.Model):
    json = models.TextField()
    errors = models.TextField(blank=True, null=True)
    publickey = models.ForeignKey(PublicKey)
    short_keyid = models.CharField(max_length=8, blank=True, null=True)
    long_keyid = models.CharField(max_length=16, blank=True, null=True)
    fingerprint = models.CharField(max_length=40, blank=True, null=True)
    created = models.DateTimeField(blank=True, null=True)
    algo_id = models.IntegerField(blank=True, null=True)

    class Meta:
        verbose_name_plural = " Sub Keys"

    @property
    def algo(self):
        return algos.PUBLICKEY_ALGORITHMS.get(self.algo_id,
            "Unknown algorithm ({})".format(self.algo_id))

    def __unicode__(self):
        return u"SubKey (id={}, keyid={}, algo={}, pubkey={})".format(self.pk, self.short_keyid, self.algo, self.publickey_id)

class UserID(models.Model):
    json = models.TextField()
    errors = models.TextField(blank=True, null=True)
    publickey = models.ForeignKey(PublicKey)
    text = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name_plural = "     User IDs"

    def __unicode__(self):
        return u"UserID (id={}, pubkey={}, text=\"{}\")".format(self.pk, self.publickey_id, self.text)

class UserAttribute(models.Model):
    json = models.TextField()
    errors = models.TextField(blank=True, null=True)
    publickey = models.ForeignKey(PublicKey)

    class Meta:
        verbose_name_plural = "   User Attributes"

    def __unicode__(self):
        return u"UserAttribute (id={}, pubkey={})".format(self.pk, self.publickey_id)

class Image(models.Model):
    userattribute = models.ForeignKey(UserAttribute)
    encoding = models.CharField(max_length=64, blank=True, null=True)
    image = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name_plural = "  Images"

    def __unicode__(self):
        return u"Image (id={}, userattribute={})".format(self.pk, self.userattribute_id)

class Signature(models.Model):
    SIGNATURE_TYPES = (
        (0, "Signature of a binary document"),
        (1, "Signature of a canonical text document"),
        (2, "Standalone signature"),
        (16, "Generic certification"),
        (17, "Persona certification"),
        (18, "Casual certification"),
        (19, "Positive certification"),
        (24, "Subkey Binding"),
        (25, "Primary Key Binding"),
        (31, "Signature directly on a key"),
        (32, "Key revocation"),
        (40, "Subkey revocation"),
        (48, "Certification revocation"),
        (64, "Timestamp"),
        (80, "Third-Party Confirmation"),
    )
    json = models.TextField()
    errors = models.TextField(blank=True, null=True)
    publickey = models.ForeignKey(PublicKey)
    subkey = models.ForeignKey(SubKey, blank=True, null=True)
    userid = models.ForeignKey(UserID, blank=True, null=True)
    userattribute = models.ForeignKey(UserAttribute, blank=True, null=True)
    signature_type = models.IntegerField(choices=SIGNATURE_TYPES, blank=True, null=True)
    is_selfsig = models.NullBooleanField(blank=True, null=True)
    signer_hex = models.CharField(max_length=16, blank=True, null=True)
    signer = models.ForeignKey(PublicKey, related_name="signer", blank=True, null=True)
    created = models.DateTimeField(blank=True, null=True)
    verified = models.NullBooleanField(blank=True, null=True)
    pubkey_algo_id = models.IntegerField(blank=True, null=True)
    hash_algo_id = models.IntegerField(blank=True, null=True)
    subpackets = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name_plural = "Signatures"

    @property
    def pubkey_algo(self):
        return algos.PUBLICKEY_ALGORITHMS.get(self.pubkey_algo_id,
            "Unknown public key algorithm ({})".format(self.pubkey_algo_id))

    @property
    def hash_algo(self):
        return algos.HASH_ALGORITHMS.get(self.hash_algo_id,
            "Unknown hash algorithm ({})".format(self.pubkey_algo_id))

    def __unicode__(self):
        if self.is_selfsig:
            return u"Self-Signature (id={}, publickey={})".format(self.pk, self.publickey_id)
        else:
            signer = self.signer_id
            if signer is None:
                signer = "Unknown ({})".format(self.signer_hex)
            return u"Signature (id={}, publickey={}, signer={})".format(self.pk, self.publickey_id, signer)




