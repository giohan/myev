from __future__ import absolute_import
import json
import os
import sys
import unittest
import logging
import base64
from StringIO import StringIO
from logging import Logger

from Crypto import Random
import mock
from moto import mock_s3, mock_kms

from myev.environment import EnvironmentStorage
from myev import environment
from myev.errors import ConfigurationFileNotFoundError, \
    ConfigurationFileInvalidMetadataError, \
    ConfigurationInvalidEnvironmentVariableNameError


# Do not allow access to AWS even if mocking is not present.
os.environ['AWS_ACCESS_KEY_ID'] = 'TEST'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'TEST'


def patched_to_json(obj):
    # Construct a JSON serialization with an ending newline in order to
    # match the encrypted sample accordingly.
    return json.JSONEncoder().encode(obj) + '\n'


class TestEnvironmentStorage(unittest.TestCase):
    def setUp(self):
        self.kms_alias = 'test-kms-alias'
        self.prefixed_kms_alias = 'alias/{}'.format(self.kms_alias)
        self.kms_key_list = {
            'Aliases': [
                {
                    'AliasName': self.prefixed_kms_alias,
                    'TargetKeyId': '3d78336b-f5c1-4bde-ab0e-1a8a2d3f1c4a'
                },
                {
                    'AliasName': 'alias/another-kms-alias',
                    'TargetKeyId': 'id-2'
                },
            ]
        }

        self.environment = EnvironmentStorage(kms_alias=self.kms_alias)
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

        self.s3_bucket = 'myev-tests-123'

    def _configure_s3(self, create_bucket=True):
        import boto3

        s3 = boto3.client('s3')
        if create_bucket:
            s3.create_bucket(Bucket=self.s3_bucket)
        return s3

    def _get_s3_path(self, key):
        return 's3://{}/{}'.format(self.s3_bucket, key)

    def test_path_construction(self):
        self.assertEqual(
            self._get_s3_path('dummy'),
            's3://myev-tests-123/dummy'
        )

    def test_init(self):
        environment = EnvironmentStorage(kms_alias=self.kms_alias)
        self.assertIsInstance(
            environment._logger,
            Logger
        )

        logger_configurator = \
            'myev.environment.EnvironmentStorage._configure_logger'

        with mock.patch(logger_configurator) as \
                mocked:
            stream = StringIO()
            _ = EnvironmentStorage(kms_alias=self.kms_alias, stream=stream)
            mocked.assert_called_once_with(stream=stream)

            _ = EnvironmentStorage(kms_alias=self.kms_alias)
            mocked.assert_called_with(stream=sys.stderr)

    def test_output(self):
        environment = EnvironmentStorage(kms_alias='test', display=mock.Mock())
        environment._output('test-1', 'error')
        environment._logger.failed.assert_called_once_with('test-1')

        with mock.patch('logging.Logger.log') as mocked_log:
            environment = EnvironmentStorage(kms_alias='test')
            test_cases = (
                ('error', logging.ERROR),
                ('info', logging.INFO),
                ('debug', logging.DEBUG)
            )
            for level, expected_level in test_cases:
                environment._output('test', level)
                mocked_log.assert_called_with(
                    msg='test',
                    level=expected_level
                )

    @mock_s3
    @mock_kms
    def test_normalize_environment_variables(self):
        environment = EnvironmentStorage(kms_alias=self.kms_alias)

        with self.assertRaises(
                ConfigurationInvalidEnvironmentVariableNameError
        ):
            environment._normalize_environment_variables({'-A': '1'})

        variables = {
            '_a0': 'test1',
            'v_E_1': 'Test2'
        }

        result = environment._normalize_environment_variables(variables)
        self.assertDictEqual(
            result,
            {
                '_A0': 'test1',
                'V_E_1': 'Test2'
            }
        )

    @mock_s3
    def test_get_bucket_does_not_exist(self):
        s3 = self._configure_s3(create_bucket=False)
        with self.assertRaises(ConfigurationFileNotFoundError):
            self.environment.get(self._get_s3_path('dummy'))

    @mock_s3
    def test_get_key_does_not_exist(self):
        self._configure_s3()
        with self.assertRaises(ConfigurationFileNotFoundError):
            self.environment.get(self._get_s3_path('dummy'))

    @mock_s3
    def test_get(self):
        s3 = self._configure_s3()
        self.environment._encryption_backend.get_object = mock.MagicMock(
            return_value={
                'Body': self.plaintext_data,
                'Metadata': {'m1': '1', 'm2': '2'}
            }
        )
        result = self.environment.get(self._get_s3_path('dummy'))
        self.assertDictEqual(
            result,
            json.loads(self.plaintext_data)
        )

    @mock_s3
    @mock_kms
    def test_get_functional(self):
        s3 = self._configure_s3(create_bucket=True)
        s3_key = 'dummy'
        s3.put_object(
            Body=base64.b64decode(self.base64_encrypted_data),
            Bucket=self.s3_bucket,
            Key=s3_key,
            Metadata=self.s3_metadata,
            ServerSideEncryption='AES256'
        )

        self.environment._encryption_backend._key_provider.decrypt = \
            mock.MagicMock(
                return_value=base64.b64decode(
                    self.base64_plaintext_envelope_key
                )
            )

        self.assertEqual(
            self.environment.get(self._get_s3_path(s3_key)),
            json.loads(self.plaintext_data)
        )

    @mock_s3
    @mock_kms
    def test_delete(self):
        s3_key = 'dummy'
        mock_s3_put_object = mock.MagicMock(
            return_value={
                'Body': 'test',
                'Metadata': {'t1': '1', 't2': '2'}
            }
        )
        self.environment._encryption_backend.put_object = mock_s3_put_object

        with mock.patch.object(EnvironmentStorage, 'get') as mock_get:
            mock_get.return_value = {
                'A_VAR': '1',
                'B_VAR': '2',
                'C_VAR': '3'
            }
            s3_path = self._get_s3_path(s3_key)
            remove_variables = ('B_VAR', 'NOT_FOUND_VAR')
            result = self.environment.delete(s3_path, remove_variables)
            expected_environment = {
                key: value
                for key, value in mock_get.return_value.items()
                if key != 'B_VAR'
            }
            self.assertDictEqual(
                expected_environment,
                result
            )

        mock_s3_put_object.assert_called_once_with(
            bucket=self.s3_bucket,
            key=s3_key,
            body=json.dumps(expected_environment).replace(' ', '')
        )

    @mock_s3
    @mock_kms
    def test_add_create(self):
        s3 = self._configure_s3()
        data = {'A': '1', 'B': '2', 'c': '3'}
        s3_key = 'dummy'

        mock_put_object = mock.MagicMock()
        self.environment._encryption_backend.put_object = mock_put_object
        result = self.environment.add(self._get_s3_path(s3_key), data)

        mock_put_object.assert_called_once_with(
            bucket=self.s3_bucket,
            key=s3_key,
            body='{"A":"1","C":"3","B":"2"}'
        )

        self.assertDictEqual(
            result,
            {"A": "1", "B": "2", "C": "3"}
        )

    @mock_s3
    @mock_kms
    @mock.patch.object(environment, 'to_json', patched_to_json)
    def test_add_create_functional(self):
        s3 = self._configure_s3()
        s3_key = 'dummy'

        key_provider = self.environment._encryption_backend._key_provider
        key_provider._client.generate_data_key = mock.MagicMock(
            return_value={
                'Plaintext': base64.b64decode(
                    self.base64_plaintext_envelope_key
                ),
                'CiphertextBlob': base64.b64decode(
                    self.s3_metadata['x-amz-key-v2']
                )
            }
        )

        key_provider._client.list_aliases = mock.MagicMock(
            return_value=self.kms_key_list
        )

        iv = base64.b64decode(self.s3_metadata['x-amz-iv'])
        crypto_random = StringIO(iv)

        with mock.patch.object(Random, 'new', return_value=crypto_random):
            self.assertDictEqual(
                self.environment.add(
                    self._get_s3_path(s3_key),
                    json.loads(self.plaintext_data)
                ),
                json.loads(self.plaintext_data)
            )

        s3_object = s3.get_object(Bucket=self.s3_bucket, Key=s3_key)
        self.assertDictEqual(
            s3_object['Metadata'],
            self.s3_metadata
        )
        self.assertIsInstance(s3_object, dict)
        self.assertEqual(
            s3_object['Body'].read(),
            base64.b64decode(self.base64_encrypted_data)
        )

    @mock_s3
    @mock_kms
    def test_add_update(self):
        s3 = self._configure_s3()

        # Cases:
        # - Existing variable, update value (A)
        # - Existing variable, unaffected value (B)
        # - New variable, normalized name (C)
        data = {'A': '3', 'B': '2', 'c': '4'}
        s3_key = 'dummy'

        mock_get_object = mock.MagicMock(
            return_value={'Body': '{"A": "1", "B": "2"}'}
        )
        self.environment._encryption_backend.get_object = mock_get_object

        mock_put_object = mock.MagicMock()
        self.environment._encryption_backend.put_object = mock_put_object

        result = self.environment.add(self._get_s3_path(s3_key), data)

        mock_get_object.assert_called_once_with(
            bucket=self.s3_bucket,
            key=s3_key
        )

        mock_put_object.assert_called_once_with(
            bucket=self.s3_bucket,
            key=s3_key,
            body='{"A":"3","C":"4","B":"2"}'

        )

        self.assertDictEqual(
            result,
            {"A": "3", "B": "2", "C": "4"}
        )
