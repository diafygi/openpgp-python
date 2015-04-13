from django.contrib import admin
from django.core.urlresolvers import reverse
from django.contrib.admin.utils import NestedObjects
from django.template.defaultfilters import unordered_list
from django.utils.safestring import mark_safe
from django.utils.html import escape
from django.contrib.admin import DateFieldListFilter
from keys import models
from keys import algos

admin.site.disable_action('delete_selected')

def _nested_objs(obj):
    c = NestedObjects("default")
    c.collect([obj])
    def format_callback(obj):
        return mark_safe('<a href="/keys/{}/{}/">{}</a>'.format(
            obj._meta.model_name, obj.pk, escape(obj)))
    result = unordered_list(c.nested(format_callback))
    return mark_safe("<ul>{}</ul>".format(result))

def _userids(obj):
    return ", ".join(models.UserID.objects.filter(
        publickey=obj).values_list("text", flat=True))

def _link_to(obj):
    return mark_safe(u'<a href="/keys/{}/{}/">{}</a>'.format(
        obj._meta.model_name, obj.pk, escape(obj)))

class AlgorithmFilter(admin.SimpleListFilter):
    title = "Public-Key Algorithm"
    parameter_name = "algo_id"
    def lookups(self, request, model_admin):
        return (
            ("RSA", "RSA"),
            ("DSA", "DSA"),
            ("ECDSA", "ECDSA"),
            ("EdDSA", "EdDSA"),
            ("Elgamal", "Elgamal"),
            ("Other", "Other"),
        )
    def queryset(self, request, queryset):
        kwargs = {}
        if self.value() == "RSA":
            kwargs["{}__in".format(self.parameter_name)] = [1, 2, 3]
            return queryset.filter(**kwargs)
        elif self.value() == "DSA":
            kwargs[self.parameter_name] = 17
            return queryset.filter(**kwargs)
        elif self.value() == "ECDSA":
            kwargs[self.parameter_name] = 19
            return queryset.filter(**kwargs)
        elif self.value() == "EdDSA":
            kwargs[self.parameter_name] = 22
            return queryset.filter(**kwargs)
        elif self.value() == "Elgamal":
            kwargs[self.parameter_name] = 16
            return queryset.filter(**kwargs)
        elif self.value() == "Other":
            kwargs["{}__in".format(self.parameter_name)] = [1, 2, 3, 17, 19, 22, 16]
            return queryset.exclude(**kwargs)

class SigAlgorithmFilter(AlgorithmFilter):
    parameter_name = "pubkey_algo_id"

class HashFilter(admin.SimpleListFilter):
    title = "Hash Algorithm Filter"
    parameter_name = "hash_algo_id"
    def lookups(self, request, model_admin):
        return (
            ("MD5", "MD5"),
            ("SHA1", "SHA1"),
            ("SHA256", "SHA256"),
            ("SHA384", "SHA384"),
            ("SHA512", "SHA512"),
            ("SHA224", "SHA224"),
            ("RIPEMD160", "RIPEMD160"),
            ("Other", "Other"),
        )
    def queryset(self, request, queryset):
        kwargs = {}
        if self.value() == "MD5":
            return queryset.filter(hash_algo_id=1)
        elif self.value() == "SHA1":
            return queryset.filter(hash_algo_id=2)
        elif self.value() == "SHA256":
            return queryset.filter(hash_algo_id=8)
        elif self.value() == "SHA384":
            return queryset.filter(hash_algo_id=9)
        elif self.value() == "SHA512":
            return queryset.filter(hash_algo_id=10)
        elif self.value() == "SHA224":
            return queryset.filter(hash_algo_id=11)
        elif self.value() == "RIPEMD160":
            return queryset.filter(hash_algo_id=3)
        elif self.value() == "Other":
            return queryset.exclude(hash_algo_id__in=[1, 2, 3, 8, 9, 10, 11])

class PublicKeyAdmin(admin.ModelAdmin):

    def nested_objs(self, obj):
        return _nested_objs(obj)

    def userids(self, obj):
        return _userids(obj)

    search_fields = (
        "id",
        "fingerprint",
        "userid__text",
    )
    list_display = (
        "short_keyid",
        "userids",
        "algo",
        "fingerprint",
        "created",
    )
    list_filter = (
        AlgorithmFilter,
        ('created', DateFieldListFilter),
    )
    ordering = (
        "id",
    )
    readonly_fields = (
        "id",
        "userids",
        "short_keyid",
        "long_keyid",
        "fingerprint",
        "created",
        "algo",
        "algo_id",
        "errors",
        "nested_objs",
    )
    fieldsets = (
        (None, {
            'fields': (
                "id",
                "userids",
                "short_keyid",
                "long_keyid",
                "fingerprint",
                "created",
                "algo",
                "algo_id",
                "errors",
                "nested_objs",
                "json",
            ),
        }),
    )
admin.site.register(models.PublicKey, PublicKeyAdmin)

class SubKeyAdmin(admin.ModelAdmin):
    raw_id_fields = ("publickey",)

    def nested_objs(self, obj):
        return _nested_objs(obj)

    def userids(self, obj):
        return _userids(obj.publickey)

    def parent_public_key(self, obj):
        return _link_to(obj.publickey)

    search_fields = (
        "id",
        "fingerprint",
        "publickey__id",
        "publickey__fingerprint",
        "publickey__userid__text",
    )
    list_display = (
        "short_keyid",
        "userids",
        "algo",
        "fingerprint",
        "created",
    )
    list_filter = (
        AlgorithmFilter,
        ('created', DateFieldListFilter),
    )
    ordering = (
        "id",
    )
    readonly_fields = (
        "parent_public_key",
        "id",
        "userids",
        "short_keyid",
        "long_keyid",
        "fingerprint",
        "created",
        "algo",
        "algo_id",
        "errors",
        "nested_objs",
    )
    fieldsets = (
        (None, {
            'fields': (
                "parent_public_key",
                "id",
                "userids",
                "short_keyid",
                "long_keyid",
                "fingerprint",
                "created",
                "algo",
                "algo_id",
                "errors",
                "nested_objs",
                "json",
            ),
        }),
    )
admin.site.register(models.SubKey, SubKeyAdmin)

class UserIDAdmin(admin.ModelAdmin):
    raw_id_fields = ("publickey",)

    def nested_objs(self, obj):
        return _nested_objs(obj)

    def userids(self, obj):
        return _userids(obj.publickey)

    def parent_public_key(self, obj):
        return _link_to(obj.publickey)

    search_fields = (
        "id",
        "text",
        "publickey__id",
        "publickey__fingerprint",
    )
    list_display = (
        "id",
        "text",
        "publickey",
    )
    ordering = (
        "id",
    )
    readonly_fields = (
        "parent_public_key",
        "id",
        "text",
        "nested_objs",
    )
    fieldsets = (
        (None, {
            'fields': (
                "parent_public_key",
                "id",
                "text",
                "nested_objs",
                "json",
            ),
        }),
    )
admin.site.register(models.UserID, UserIDAdmin)

class UserAttributeAdmin(admin.ModelAdmin):
    raw_id_fields = ("publickey",)

    def nested_objs(self, obj):
        return _nested_objs(obj)

    def images(self, obj):
        return mark_safe(", ".join(_link_to(i) for i in models.Image.objects.filter(userattribute=obj)))

    def parent_public_key(self, obj):
        return _link_to(obj.publickey)

    search_fields = (
        "id",
        "fingerprint",
        "publickey__id",
        "publickey__fingerprint",
        "publickey__userid__text",
    )
    list_display = (
        "__str__",
        "images",
        "publickey",
    )
    ordering = (
        "id",
    )
    readonly_fields = (
        "parent_public_key",
        "id",
        "images",
        "nested_objs",
    )
    fieldsets = (
        (None, {
            'fields': (
                "parent_public_key",
                "id",
                "images",
                "nested_objs",
                "json",
            ),
        }),
    )
admin.site.register(models.UserAttribute, UserAttributeAdmin)

class ImageAdmin(admin.ModelAdmin):
    raw_id_fields = ("userattribute",)

    def image_jpeg(self, obj):
        return mark_safe("<a href='/keys/image/{}/'><img src='data:image/jpeg;base64,{}' \
style='max-height:100px;max-width:100px;'></a>".format(obj.pk, escape(obj.image)))

    def userids(self, obj):
        return _userids(obj.userattribute.publickey)

    def parent_public_key(self, obj):
        return _link_to(obj.userattribute.publickey)

    def parent_user_attribute(self, obj):
        return _link_to(obj.userattribute)

    def user_publickey(self, obj):
        return str(obj.userattribute.publickey)

    search_fields = (
        "id",
        "userattribute__publickey__id",
        "userattribute__publickey__fingerprint",
        "userattribute__publickey__userid__text",
    )
    list_display = (
        "id",
        "image_jpeg",
        "parent_public_key",
        "userids",
        "parent_user_attribute",
    )
    ordering = (
        "id",
    )
    readonly_fields = (
        "parent_public_key",
        "parent_user_attribute",
        "id",
        "image_jpeg",
    )
    fieldsets = (
        (None, {
            'fields': (
                "parent_public_key",
                "parent_user_attribute",
                "id",
                "image_jpeg",
                "image",
            ),
        }),
    )
admin.site.register(models.Image, ImageAdmin)

class SignatureAdmin(admin.ModelAdmin):
    raw_id_fields = ("publickey", "subkey", "userid", "userattribute", "signer")

    def userids(self, obj):
        return _userids(obj.publickey)

    def signer_link(self, obj):
        if obj.signer_id:
            return _link_to(obj.signer)
        else:
            return "Unknown ({})".format(obj.signer_hex)

    def parent_public_key(self, obj):
        return _link_to(obj.publickey)

    def signature_target(self, obj):
        if obj.subkey:
            return _link_to(obj.subkey)
        elif obj.userid:
            return _link_to(obj.userid)
        elif obj.userid:
            return _link_to(obj.userid)
        elif obj.userattribute:
            return _link_to(obj.userattribute)
        else:
            return _link_to(obj.publickey)

    search_fields = (
        "id",
        "publickey__id",
        "publickey__fingerprint",
        "publickey__userid__text",
        "signer__id",
        "signer__fingerprint",
        "signer__userid__text",
    )
    list_display = (
        "id",
        "signature_type",
        "is_selfsig",
        "created",
        "pubkey_algo",
        "hash_algo",
        "signature_target",
        "parent_public_key",
        "signer_link",
    )
    list_filter = (
        SigAlgorithmFilter,
        HashFilter,
        ('created', DateFieldListFilter),
        "is_selfsig",
        "verified",
    )
    ordering = (
        "id",
    )
    readonly_fields = (
        "parent_public_key",
        "id",
        "signature_type",
        "is_selfsig",
        "verified",
        "created",
        "pubkey_algo",
        "hash_algo",
        "signature_target",
        "signer_link",
        "errors",
    )
    fieldsets = (
        (None, {
            'fields': (
                "parent_public_key",
                "id",
                "signature_type",
                "is_selfsig",
                "verified",
                "created",
                "pubkey_algo",
                "hash_algo",
                "signature_target",
                "signer_link",
                "errors",
                "json",
            ),
        }),
    )
admin.site.register(models.Signature, SignatureAdmin)
