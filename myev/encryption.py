#!/usr/bin/env python
import base64
import json
import logging
from urlparse import urlparse

import boto3
import botocore
from Crypto import Random
from Crypto.Cipher import AES

from myev.errors import (
    KMSAliasNotFoundError,
    ConfigurationFileNotFoundError
)
from myev.utils import pkcs5_pad, to_base64, to_json


module_logger = logging.getLogger(__name__)


class KMSClient(object):
    def __init__(self, alias, region=None):
        self._alias = None
        self.set_alias(alias)
        self._region = region
        self._client = boto3.client('kms', region_name=self._region)

    @property
    def alias(self):
        """
        :rtype: str
        """
        return self._alias

    def set_alias(self, value):
        """
        Update the KMS alias, if it has not been set during the construction.
        :param str|None value: the KMS alias
        :rtype: bool
        """
        if self._alias is None:
            if value is not None:
                self._alias = self._normalize_alias(value)
            else:
                self._alias = value
            return True
        return False

    @staticmethod
    def _normalize_alias(name):
        """
        Prepend the 'alias/' namespace for the given KMS alias.
        :param str name: the given alias.
        :rtype: str
        """
        if not name.startswith('alias/'):
            name = 'alias/{}'.format(name)
        return name

    def _get_key_id(self):
        """
        Retrieve the KMS Key ID for the given alias.
        :rtype: str|None
        :return: the key ID or None if it was not found.
        """

        if self._alias is None:
            return

        kms = self._client
        aliases = kms.list_aliases()['Aliases']

        # Find the KMS id for the user provided alias.
        for alias in aliases:
            if alias['AliasName'] == self._alias:
                return alias['TargetKeyId']

    def get_key_alias(self, key_id):
        """
        Retrieve the KMS Key Alias for the given ID.
        :rtype: str|None
        :return: the key alias or None if it was not found.
        """
        kms = self._client
        aliases = kms.list_aliases()['Aliases']

        # Find the KMS id for the user provided alias.
        for alias in aliases:
            # AWS auto-generated keys do not contain the field TargetKeyId.
            if 'TargetKeyId' in alias:
                if alias['TargetKeyId'] == key_id:
                    return alias['AliasName']

    def generate_envelope_key(self):
        kms_id = self._get_key_id()

        if kms_id is None:
            raise KMSAliasNotFoundError(
                "Key ID not found for alias: {}".format(self._alias)
            )

        kms = self._client

        encryption_context = {"kms_cmk_id": kms_id}

        key_data = kms.generate_data_key(
            KeyId=kms_id,
            EncryptionContext=encryption_context,
            KeySpec="AES_256"
        )
        key_data.update(dict(EncryptionContext=encryption_context))

        return key_data

    def decrypt(self, encrypted_content, encryption_context):
        """
        Decrypt a string via KMS.
        :param str encrypted_content:
        :param dict[str] encryption_context:
        :return:
        """
        kms = self._client
        response = kms.decrypt(
            CiphertextBlob=encrypted_content,
            EncryptionContext=encryption_context
        )
        return response['Plaintext']


class S3EncryptionClient(object):
    def __init__(self, key_provider):
        assert isinstance(key_provider, KMSClient)

        self._key_provider = key_provider
        self._client = boto3.client('s3')

    @property
    def key_provider(self):
        """
        :rtype: KMSClient
        """
        return self._key_provider

    @staticmethod
    def encrypt(key, content, iv, chunk_size=16):
        cipher = AES.new(key, AES.MODE_CBC, iv)

        output = ''
        chunk = None

        while True:
            chunk = content[:chunk_size]
            content = content[chunk_size:]
            last_chunk_length = len(chunk)
            if last_chunk_length == 0 or last_chunk_length < chunk_size:
                break
            output += cipher.encrypt(chunk)

        output += cipher.encrypt(pkcs5_pad(chunk))
        return output

    @staticmethod
    def decrypt(key, content, iv, unencrypted_length, chunk_size=16):
        aes = AES.new(key, AES.MODE_CBC, iv)

        output = ''

        while True:
            chunk = content.read(chunk_size)
            if len(chunk) == 0:
                break
            output += aes.decrypt(chunk)

        return output[:unencrypted_length]

    @staticmethod
    def _prepare_encryption_metadata(
        encrypted_envelope_key,
        iv,
        encryption_context,
        unencrypted_content_length
    ):
        return {
            'x-amz-key-v2': to_base64(encrypted_envelope_key),
            'x-amz-iv': to_base64(iv),
            'x-amz-cek-alg': 'AES/CBC/PKCS5Padding',
            'x-amz-wrap-alg': 'kms',
            'x-amz-matdesc': to_json(encryption_context),
            'x-amz-unencrypted-content-length': str(unencrypted_content_length)
        }

    def put_object(self, bucket, key, body):
        key_data = self._key_provider.generate_envelope_key()
        encryption_context = key_data['EncryptionContext']
        plaintext_key = key_data['Plaintext']
        encrypted_key = key_data['CiphertextBlob']

        iv = Random.new().read(AES.block_size)
        unencrypted_length = len(body)

        encrypted_content = self.encrypt(plaintext_key, body, iv)
        metadata = self._prepare_encryption_metadata(
            encrypted_envelope_key=encrypted_key,
            iv=iv,
            encryption_context=encryption_context,
            unencrypted_content_length=unencrypted_length
        )

        return self._client.put_object(
            Body=encrypted_content,
            Bucket=bucket,
            Key=key,
            Metadata=metadata,
            ServerSideEncryption='AES256'
        )

    def get_object(self, bucket, key):
        try:
            s3_object = self._client.get_object(Bucket=bucket, Key=key)
        except botocore.exceptions.ClientError:
            raise ConfigurationFileNotFoundError(
                'S3 error: check if the given S3 Path exists '
                '(Bucket={}, Key={}).'.format(bucket, key)
            )

        # Get object metadata for the encrypted object and
        # decode base64-encoded strings.
        metadata = s3_object['Metadata']
        envelope_key = base64.b64decode(metadata['x-amz-key-v2'])
        iv = base64.b64decode(metadata['x-amz-iv'])
        encryption_context = json.loads(metadata['x-amz-matdesc'])
        unencrypted_length = int(metadata['x-amz-unencrypted-content-length'])

        # Update the alias so we can proceed with further operations
        # on the same item.
        if self._key_provider.alias is None:
            self._key_provider.set_alias(
                self._key_provider.get_key_alias(
                    key_id=encryption_context.get('kms_cmk_id')
                )
            )

        # Use AWS KMS to decrypt envelop key (envelop key is used to encrypt
        # object data)
        decrypted_envelope_key = self._key_provider.decrypt(
            encrypted_content=envelope_key,
            encryption_context=encryption_context
        )

        s3_object['Body'] = self.decrypt(
            key=decrypted_envelope_key,
            content=s3_object['Body'],
            iv=iv,
            unencrypted_length=unencrypted_length
        )

        return s3_object

    @staticmethod
    def s3_path_split(object_path):
        if not object_path.startswith('s3://'):
            object_path = 's3://{}'.format(object_path)

        parsed_path = urlparse(object_path)
        bucket = parsed_path.netloc
        key = parsed_path.path.strip('/')
        return bucket, key
