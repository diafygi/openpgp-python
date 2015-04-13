# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Image',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('encoding', models.CharField(max_length=64, null=True, blank=True)),
                ('image', models.TextField(null=True, blank=True)),
            ],
            options={
                'verbose_name_plural': '  Images',
            },
        ),
        migrations.CreateModel(
            name='PublicKey',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('json', models.TextField()),
                ('errors', models.TextField(null=True, blank=True)),
                ('short_keyid', models.CharField(max_length=8, null=True, blank=True)),
                ('long_keyid', models.CharField(db_index=True, max_length=16, null=True, blank=True)),
                ('fingerprint', models.CharField(max_length=40, null=True, blank=True)),
                ('created', models.DateTimeField(null=True, blank=True)),
                ('algo_id', models.IntegerField(null=True, blank=True)),
            ],
            options={
                'verbose_name_plural': '      Public Keys',
            },
        ),
        migrations.CreateModel(
            name='Signature',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('json', models.TextField()),
                ('errors', models.TextField(null=True, blank=True)),
                ('signature_type', models.IntegerField(blank=True, null=True, choices=[(0, b'Signature of a binary document'), (1, b'Signature of a canonical text document'), (2, b'Standalone signature'), (16, b'Generic certification'), (17, b'Persona certification'), (18, b'Casual certification'), (19, b'Positive certification'), (24, b'Subkey Binding'), (25, b'Primary Key Binding'), (31, b'Signature directly on a key'), (32, b'Key revocation'), (40, b'Subkey revocation'), (48, b'Certification revocation'), (64, b'Timestamp'), (80, b'Third-Party Confirmation')])),
                ('is_selfsig', models.NullBooleanField()),
                ('signer_hex', models.CharField(max_length=16, null=True, blank=True)),
                ('created', models.DateTimeField(null=True, blank=True)),
                ('verified', models.NullBooleanField()),
                ('pubkey_algo_id', models.IntegerField(null=True, blank=True)),
                ('hash_algo_id', models.IntegerField(null=True, blank=True)),
                ('subpackets', models.TextField(null=True, blank=True)),
                ('publickey', models.ForeignKey(to='keys.PublicKey')),
                ('signer', models.ForeignKey(related_name='signer', blank=True, to='keys.PublicKey', null=True)),
            ],
            options={
                'verbose_name_plural': 'Signatures',
            },
        ),
        migrations.CreateModel(
            name='SubKey',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('json', models.TextField()),
                ('errors', models.TextField(null=True, blank=True)),
                ('short_keyid', models.CharField(max_length=8, null=True, blank=True)),
                ('long_keyid', models.CharField(max_length=16, null=True, blank=True)),
                ('fingerprint', models.CharField(max_length=40, null=True, blank=True)),
                ('created', models.DateTimeField(null=True, blank=True)),
                ('algo_id', models.IntegerField(null=True, blank=True)),
                ('publickey', models.ForeignKey(to='keys.PublicKey')),
            ],
            options={
                'verbose_name_plural': ' Sub Keys',
            },
        ),
        migrations.CreateModel(
            name='UserAttribute',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('json', models.TextField()),
                ('errors', models.TextField(null=True, blank=True)),
                ('publickey', models.ForeignKey(to='keys.PublicKey')),
            ],
            options={
                'verbose_name_plural': '   User Attributes',
            },
        ),
        migrations.CreateModel(
            name='UserID',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('json', models.TextField()),
                ('errors', models.TextField(null=True, blank=True)),
                ('text', models.TextField(null=True, blank=True)),
                ('publickey', models.ForeignKey(to='keys.PublicKey')),
            ],
            options={
                'verbose_name_plural': '     User IDs',
            },
        ),
        migrations.AddField(
            model_name='signature',
            name='subkey',
            field=models.ForeignKey(blank=True, to='keys.SubKey', null=True),
        ),
        migrations.AddField(
            model_name='signature',
            name='userattribute',
            field=models.ForeignKey(blank=True, to='keys.UserAttribute', null=True),
        ),
        migrations.AddField(
            model_name='signature',
            name='userid',
            field=models.ForeignKey(blank=True, to='keys.UserID', null=True),
        ),
        migrations.AddField(
            model_name='image',
            name='userattribute',
            field=models.ForeignKey(to='keys.UserAttribute'),
        ),
    ]
