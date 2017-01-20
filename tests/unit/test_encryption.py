from __future__ import absolute_import
import base64
import json
import os
import unittest
from StringIO import StringIO


from Crypto import Random
import mock
from moto import mock_s3, mock_kms

from myev.utils import to_base64
from myev.encryption import KMSClient, S3EncryptionClient
from myev.errors import ConfigurationFileNotFoundError, \
    KMSAliasNotFoundError


# Do not allow access to AWS even if mocking is not present.
os.environ['AWS_ACCESS_KEY_ID'] = 'TEST'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'TEST'


class TestKMSClient(unittest.TestCase):
    def setUp(self):
        self.kms_alias = 'test-kms-alias'
        self.prefixed_kms_alias = 'alias/{}'.format(self.kms_alias)
        self.kms_key_list = {
            'Aliases': [
                {
                    'AliasName': self.prefixed_kms_alias,
                    'TargetKeyId': 'id-1'
                },
                {
                    'AliasName': 'alias/{}'.format('another-kms-alias'),
                    'TargetKeyId': 'id-2'
                },
                # Verify that no KeyError is generated if TargetKeyId is
                # missing.
                {
                    'AliasName': 'alias/aws/DEFAULT',
                    'AliasArn': 'testARN'
                }
            ]
        }

    @mock_kms
    def test_init(self):
        with mock.patch('boto3.client') as mock_client:
            kms_client = KMSClient(alias=self.kms_alias)

            self.assertIsNone(kms_client._region)
            self.assertEqual(kms_client._alias, self.prefixed_kms_alias)
            mock_client.assert_called_with('kms', region_name=None)

            kms_client = KMSClient(alias=self.kms_alias, region='us-test-1')

            self.assertEqual(kms_client._region, 'us-test-1')
            self.assertEqual(kms_client._alias, self.prefixed_kms_alias)
            mock_client.assert_called_with('kms', region_name='us-test-1')

            # Test with non-string (None) KMS alias
            kms_client = KMSClient(alias=None)
            self.assertIsNone(kms_client._alias)

    @mock_kms
    def test_set_alias(self):
        kms_client = KMSClient(alias='test')
        self.assertEqual(
            kms_client.alias,
            'alias/test'
        )
        self.assertFalse(kms_client.set_alias('something-else'))
        self.assertEqual(
            kms_client.alias,
            'alias/test'
        )

        kms_client = KMSClient(alias=None)
        self.assertIsNone(kms_client.alias)

        self.assertTrue(kms_client.set_alias('something-else'))
        self.assertEqual(
            kms_client.alias,
            'alias/something-else'
        )

    def test_normalize_alias(self):
        function = KMSClient._normalize_alias

        cases = (
            ('test', 'alias/test'),
            ('alias/test2', 'alias/test2'),
            ('al/test', 'alias/al/test'),
        )
        for given, expected in cases:
            self.assertEqual(
                expected,
                function(given)
            )

    @mock_kms
    def test_get_key_id(self):
        kms_client = KMSClient(alias=self.prefixed_kms_alias)
        kms_client._client = mock.Mock()
        kms_client._client.list_aliases = mock.MagicMock(
            return_value=self.kms_key_list
        )
        self.assertEqual(
            kms_client._get_key_id(),
            'id-1'
        )
        self.kms_key_list['Aliases'] = self.kms_key_list['Aliases'][1:]
        self.assertIsNone(kms_client._get_key_id())

        # Raise Error if used without alias
        kms_client = KMSClient(alias=None)
        with self.assertRaises(KMSAliasNotFoundError):
            kms_client.generate_envelope_key()

    @mock_kms
    def test_get_key_id_no_prefix(self):
        # Test without the 'alias/' prefix
        kms_client = KMSClient(alias=self.kms_alias)
        kms_client._client = mock.Mock()
        kms_client._client.list_aliases = mock.MagicMock(
            return_value=self.kms_key_list
        )
        self.assertEqual(
            kms_client._get_key_id(),
            'id-1'
        )

    @mock_kms
    def test_get_key_alias(self):
        kms_client = KMSClient(alias=None)
        kms_client._client = mock.Mock()
        kms_client._client.list_aliases = mock.MagicMock(
            return_value=self.kms_key_list
        )
        self.assertIsNone(kms_client.get_key_alias('unknown-id'))

        self.assertEqual(
            kms_client.get_key_alias('id-2'),
            self.kms_key_list['Aliases'][1]['AliasName']
        )

    @mock_kms
    def test_decrypt(self):
        kms_client = KMSClient(alias=self.kms_alias)
        kms_client._client = mock.Mock()
        kms_client._client.decrypt = mock.MagicMock(
            return_value={'Plaintext': 'test'}
        )

        result = kms_client.decrypt(
            encrypted_content='a',
            encryption_context={'t': 1}
        )
        self.assertEqual(result, 'test')

        kms_client._client.decrypt.assert_called_once_with(
            CiphertextBlob='a',
            EncryptionContext={'t': 1}
        )

    @mock_kms
    def test_generate_envelope_key(self):
        with self.assertRaises(KMSAliasNotFoundError):
            kms_client = KMSClient(alias='unknown-kms-alias')
            kms_client._client.list_aliases = mock.MagicMock(
                return_value=self.kms_key_list
            )
            kms_client.generate_envelope_key()

        kms_generated_envelope_key = {
            'Plaintext': 'test_plaintext',
            'CiphertextBlob': 'test_ciphertext_blob'
        }

        kms_client = KMSClient(alias=self.kms_alias)
        kms_client._client = mock.Mock()
        kms_client._client.generate_data_key = mock.MagicMock(
            return_value=kms_generated_envelope_key.copy()
        )
        kms_client._client.list_aliases = mock.MagicMock(
            return_value=self.kms_key_list
        )

        kms_generated_envelope_key.update(
            dict(EncryptionContext={'kms_cmk_id': 'id-1'})
        )

        result = kms_client.generate_envelope_key()
        self.assertDictEqual(
            result,
            kms_generated_envelope_key
        )
        kms_client._client.generate_data_key.assert_called_once_with(
            KeyId='id-1',
            EncryptionContext={'kms_cmk_id': 'id-1'},
            KeySpec="AES_256"
        )


class TestS3EncryptionClient(unittest.TestCase):
    def setUp(self):
        self.s3_bucket = 'myev-tests-123'
        # Sample data encrypted and uploaded by the Ruby SDK
        self.s3_metadata = {
            'x-amz-cek-alg': 'AES/CBC/PKCS5Padding',
            'x-amz-iv': 'wyqRlcTfa8qtvYc2AZM1vg==',
            'x-amz-key-v2':
                'AQEDAHgwrsK9FliCzxfzK2/qJ7ZEc5ZWM8q9WzJgY/ldZTG'
                'jigAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAW'
                'UDBAEuMBEEDJ2oZHkbpznDeSlu3AIBEIA7C9G+Y5BtdSsd2hns8r3dvQKzZ0R/fV'
                'd9gbiHZ7/aIoC0+Hwthq+/grWjWlQvOnfDk9F8sK7dO7rWXeM=',
            'x-amz-matdesc':
                '{"kms_cmk_id":"3d78336b-f5c1-4bde-ab0e-1a8a2d3f1c4a"}',
            'x-amz-unencrypted-content-length': '45',
            'x-amz-wrap-alg': 'kms'
        }
        self.plaintext_data = '{"A": "1", "B": "abcdefghijklmnopqrstuvxyz"}\n'
        self.base64_encrypted_data = \
            'Vjg8GFTZds+gVhCTP9H+YgfiVifJDSCljtwde46LSLesamFf1Vfz/4v1YGITDlUM'

        self.base64_plaintext_envelope_key = \
            'tUQZbnbmv1woZhiW7UulhWe3xfNHERnxRoVcjHk5a7w='
        self.kms_alias = 'alias/test-kms-alias'
        self.kms_key_list = {
            'Aliases': [
                {
                    'AliasName': self.kms_alias,
                    'TargetKeyId': 'id-1'
                },
                {
                    'AliasName': 'alias/another-kms-alias',
                    'TargetKeyId': 'id-2'
                },
            ]
        }
        self.kms_client = KMSClient(alias=self.kms_alias)


    @mock_s3
    def _configure_s3(self, create_bucket=True):
        import boto3

        s3 = boto3.client('s3')
        s3.create_bucket(Bucket=self.s3_bucket)
        return s3

    def _get_s3_path(self, key):
        return 's3://{}/{}'.format(self.s3_bucket, key)

    def test_helper_path_construction(self):
        self.assertEqual(
            self._get_s3_path('dummy'),
            's3://myev-tests-123/dummy'
        )

    def test_init(self):
        with self.assertRaises(AssertionError):
            S3EncryptionClient(key_provider='invalid_object')

        client = S3EncryptionClient(key_provider=self.kms_client)
        self.assertIs(client._key_provider, self.kms_client)
        self.assertRegexpMatches(
            str(client._client),
            "<botocore.client.S3 object at 0x.*?>"
        )

    @mock_s3
    @mock_kms
    def test_encrypt(self):
        client = S3EncryptionClient(key_provider=self.kms_client)
        for chunk_size in (16, 32):
            encrypted_content = client.encrypt(
                content=self.plaintext_data,
                key=base64.b64decode(self.base64_plaintext_envelope_key),
                iv=base64.b64decode(self.s3_metadata['x-amz-iv']),
                chunk_size=chunk_size
            )
            base64_encrypted_content = base64.b64encode(encrypted_content)
            self.assertEqual(
                base64_encrypted_content,
                self.base64_encrypted_data
            )

    @mock_s3
    @mock_kms
    def test_decrypt(self):
        client = S3EncryptionClient(key_provider=self.kms_client)
        for chunk_size in (16, 32, 48, 64):
            encrypted_content = StringIO(
                base64.b64decode(self.base64_encrypted_data)
            )
            decrypted = client.decrypt(
                content=encrypted_content,
                key=base64.b64decode(self.base64_plaintext_envelope_key),
                iv=base64.b64decode(self.s3_metadata['x-amz-iv']),
                unencrypted_length=int(
                    self.s3_metadata['x-amz-unencrypted-content-length']
                ),
                chunk_size=chunk_size
            )
            self.assertEqual(
                decrypted,
                self.plaintext_data
            )

    @mock_kms
    @mock_s3
    def test_prepare_encryption_metadata(self):
        unencrypted_length = 10
        metadata = dict(
            encrypted_envelope_key='test_envelope_key',
            iv='test_iv',
            encryption_context={'ctx': 'a'},
            unencrypted_content_length=unencrypted_length
        )

        result = S3EncryptionClient._prepare_encryption_metadata(**metadata)
        self.assertDictEqual(
            result,
            {
                'x-amz-key-v2': to_base64(metadata['encrypted_envelope_key']),
                'x-amz-iv': to_base64(metadata['iv']),
                'x-amz-cek-alg': 'AES/CBC/PKCS5Padding',
                'x-amz-wrap-alg': 'kms',
                'x-amz-matdesc': '{"ctx":"a"}',
                'x-amz-unencrypted-content-length': str(unencrypted_length)
            }
        )

    @mock_kms
    @mock_s3
    def test_s3_path_split(self):
        cases = (
            {
                's3_path': '',
                'result': ('', '')
            },
            {
                's3_path': 's3://',
                'result': ('', '')
            },
            {
                's3_path': 'a/b',
                'result': ('a', 'b')
            },
            {
                's3_path': 's3://a/b',
                'result': ('a', 'b')
            },
            {
                's3_path': 's3://a/b/c',
                'result': ('a', 'b/c')
            },
            {
                's3_path': 's3://a/b/c.txt',
                'result': ('a', 'b/c.txt')
            },
        )
        for case in cases:
            result = S3EncryptionClient.s3_path_split(case['s3_path'])
            self.assertTupleEqual(
                case['result'],
                result
            )

    @mock_s3
    @mock_kms
    def test_put_object(self):
        s3_key = 'dummy'

        encryption_client = S3EncryptionClient(key_provider=self.kms_client)
        encryption_client._key_provider = mock.MagicMock()
        encryption_client._key_provider.generate_envelope_key = \
            mock.MagicMock(
                return_value={
                    'Plaintext': base64.b64decode(
                        self.base64_plaintext_envelope_key
                    ),
                    'CiphertextBlob': base64.b64decode(
                        self.s3_metadata['x-amz-key-v2']
                    ),
                    'EncryptionContext': json.loads(
                        self.s3_metadata['x-amz-matdesc']
                    )
                }
            )
        encryption_client._client = mock.MagicMock()
        encryption_client._client.put_object = mock.MagicMock(
            return_value={'tested-operation': 's3_put_object'}
        )

        iv = base64.b64decode(self.s3_metadata['x-amz-iv'])
        crypto_random = StringIO(iv)

        mock_generate_envelope_key = \
            encryption_client._key_provider.generate_envelope_key

        mock_put_object = encryption_client._client.put_object

        with mock.patch.object(Random, 'new', return_value=crypto_random):
            result = encryption_client.put_object(
                bucket=self.s3_bucket,
                key=s3_key,
                body=self.plaintext_data
            )
            mock_generate_envelope_key.assert_called_once_with()
            self.assertDictEqual(
                result,
                {'tested-operation': 's3_put_object'}
            )
            mock_put_object.assert_called_once_with(
                Body=base64.b64decode(self.base64_encrypted_data),
                Bucket=self.s3_bucket,
                Key=s3_key,
                Metadata=self.s3_metadata,
                ServerSideEncryption='AES256'
            )

    @mock_s3
    @mock_kms
    def test_get_object(self):
        from botocore.exceptions import ClientError
        s3_key = 'dummy'

        encryption_client = S3EncryptionClient(key_provider=self.kms_client)
        encryption_client._client = mock.MagicMock()
        encryption_client._client.get_object = mock.Mock(
            side_effect=ClientError(
                {'Error': {'Code': 'Unknown Error'}},
                'S3'
            )
        )

        with self.assertRaises(ConfigurationFileNotFoundError):
            encryption_client.get_object(
                bucket=self.s3_bucket,
                key=s3_key
            )

        encryption_client._client.get_object.assert_called_once_with(
            Bucket=self.s3_bucket,
            Key=s3_key
        )

        encryption_client = S3EncryptionClient(key_provider=self.kms_client)
        encryption_client._client = mock.MagicMock()
        encryption_client._client.get_object = mock.MagicMock(
            return_value={
                'Metadata': self.s3_metadata,
                'Body': StringIO(
                    base64.b64decode(self.base64_encrypted_data)
                )
            }
        )
        encryption_client._key_provider = mock.MagicMock()
        encryption_client._key_provider.decrypt = \
            mock.MagicMock(
                return_value=base64.b64decode(
                    self.base64_plaintext_envelope_key
                )
            )

        result = encryption_client.get_object(
            bucket=self.s3_bucket,
            key=s3_key
        )

        encryption_client._key_provider.decrypt.assert_called_once_with(
            encrypted_content=base64.b64decode(
                self.s3_metadata['x-amz-key-v2']
            ),
            encryption_context=json.loads(self.s3_metadata['x-amz-matdesc'])
        )

        self.assertDictEqual(
            result,
            {
                'Body': self.plaintext_data,
                'Metadata': self.s3_metadata
            }
        )

    @mock_s3
    @mock_kms
    def test_get_object_update_alias_from_metadata(self):
        s3_key = 'dummy'

        kms_client = KMSClient(alias=None)
        encryption_client = S3EncryptionClient(key_provider=kms_client)

        original_set_alias = kms_client.set_alias

        self.assertIsNone(encryption_client._key_provider.alias)

        encryption_client._client = mock.MagicMock()
        encryption_client._client.get_object = mock.MagicMock(
            return_value={
                'Metadata': self.s3_metadata,
                'Body': StringIO(
                    base64.b64decode(self.base64_encrypted_data)
                )
            }
        )
        encryption_client._key_provider = mock.MagicMock()
        encryption_client._key_provider.decrypt = \
            mock.MagicMock(
                return_value=base64.b64decode(
                    self.base64_plaintext_envelope_key
                )
            )

        mock_get_key_alias = encryption_client._key_provider.get_key_alias = \
            mock.MagicMock(return_value='test')

        encryption_client._key_provider.alias = None
        mock_set_alias = encryption_client._key_provider.set_alias = \
            mock.MagicMock(side_effect=original_set_alias)

        encryption_client.get_object(
            bucket=self.s3_bucket,
            key=s3_key
        )

        mock_get_key_alias.assert_called_once_with(
            key_id=json.loads(self.s3_metadata['x-amz-matdesc'])['kms_cmk_id']
        )
        mock_set_alias.assert_called_once_with('test')
        self.assertEqual(kms_client._alias, 'alias/test')
