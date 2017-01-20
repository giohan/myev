from __future__ import absolute_import
import os
import unittest

import mock
from moto import mock_s3, mock_kms
import click
from click.testing import CliRunner

from myev import errors
from myev.main import add, get, delete, exception_handler


# Do not allow access to AWS even if mocking is not present.
os.environ['AWS_ACCESS_KEY_ID'] = 'TEST'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'TEST'


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_exception_handler(self):
        def fn():
            raise KeyError('Test!')

        with self.assertRaises(click.ClickException):
            exception_handler(fn)()

        with self.assertRaisesRegexp(
            click.ClickException,
            '^KeyError: Test!$'
        ):
            exception_handler(fn)()

    @mock_kms
    @mock_s3
    def test_add(self):
        with mock.patch('myev.main.EnvironmentStorage') as mock_storage:
            result = self.runner.invoke(
                add,
                [
                    '--s3-path',
                    'myev-tests-123/dummy',
                    '--kms-alias',
                    'test-kms-alias',
                    'A=1'
                ]
            )

            mock_storage.assert_called_once_with(
                kms_alias='test-kms-alias',
                region=None
            )
            mock_storage.return_value.add.assert_called_once_with(
                s3_path='myev-tests-123/dummy',
                variables={'A': '1'}
            )
            self.assertEqual(result.exit_code, 0)

    @mock_kms
    @mock_s3
    def test_add_invalid_variables(self):
        with mock.patch('myev.main.EnvironmentStorage') as mock_storage:
            result = self.runner.invoke(
                add,
                [
                    '--s3-path',
                    'myev-tests-123/dummy',
                    '--kms-alias',
                    'test-kms-alias',
                    'A=1',
                    'B'
                ]
            )
            self.assertIsInstance(
                result.exception,
                SystemExit
            )
            self.assertEqual(result.exit_code, 1)

    @mock_kms
    @mock_s3
    def test_add_file_initialization(self):
        # Verify that an error is raised if the file does not exist
        # and must be added and the --kms-alias parameter has not been given.
        with mock.patch('myev.main.EnvironmentStorage') as mock_storage:
            mock_storage.return_value.add = mock.MagicMock(
                side_effect=errors.KMSAliasNotFoundError()
            )
            result = self.runner.invoke(
                add,
                [
                    '--s3-path',
                    'myev-tests-123/dummy',
                    'A=1'
                ]
            )
            self.assertIsInstance(
                result.exception,
                SystemExit
            )
            self.assertEqual(result.exit_code, 1)

    @mock_kms
    @mock_s3
    def test_delete(self):
        with mock.patch('myev.main.EnvironmentStorage') as mock_storage:
            result = self.runner.invoke(
                delete,
                [
                    '--s3-path',
                    'myev-tests-123/dummy',
                    'A',
                    'B'
                ],
                input='y'
            )

            self.assertEqual(
                result.output,
                "Are you sure you want to delete the "
                "variables 'A, B'? [y/N]: y\n"
            )

            mock_storage.assert_called_once_with(
                kms_alias=None,
                region=None
            )
            mock_storage.return_value.delete.assert_called_once_with(
                s3_path='myev-tests-123/dummy',
                variables=('A', 'B')
            )
            self.assertEqual(result.exit_code, 0)

    @mock_kms
    @mock_s3
    def test_get_invalid_s3_path(self):
        with mock.patch('myev.main.EnvironmentStorage') as mock_storage:
            mock_get = mock_storage.return_value.get = mock.MagicMock(
                side_effect=errors.ConfigurationFileNotFoundError
            )
            result = self.runner.invoke(
                get,
                [
                    '--s3-path',
                    'myev-tests-123/dummy'
                ]
            )

            self.assertIsInstance(result.exception, SystemExit)

            mock_storage.assert_called_once_with(
                kms_alias=None,
                region=None
            )
            self.assertEqual(result.exit_code, 1)

    @mock_kms
    @mock_s3
    def test_get_invalid_variable_name(self):
        with mock.patch('myev.main.EnvironmentStorage') as mock_storage:
            mock_get = mock_storage.return_value.get = mock.MagicMock(
                return_value={'A': '1', 'B': '2'}
            )
            result = self.runner.invoke(
                get,
                [
                    '--s3-path',
                    'myev-tests-123/dummy',
                    'C'
                ]
            )

            self.assertIsInstance(result.exception, SystemExit)

            mock_storage.assert_called_once_with(
                kms_alias=None,
                region=None
            )
            self.assertEqual(result.exit_code, 1)

    @mock_kms
    @mock_s3
    def test_get_specific_variables(self):
        with mock.patch('myev.main.EnvironmentStorage') as mock_storage:
            mock_get = mock_storage.return_value.get = mock.MagicMock(
                return_value={'A': '1', 'B': '2'}
            )
            result = self.runner.invoke(
                get,
                [
                    '--s3-path',
                    'myev-tests-123/dummy',
                    'A'
                ]
            )

            self.assertEqual(result.output, 'A=1\n')
            mock_storage.assert_called_once_with(
                kms_alias=None,
                region=None
            )
            mock_get.assert_called_once_with(s3_path='myev-tests-123/dummy')
            self.assertEqual(result.exit_code, 0)

    @mock_kms
    @mock_s3
    def test_get_special_character_value(self):
        with mock.patch('myev.main.EnvironmentStorage') as mock_storage:
            mock_get = mock_storage.return_value.get = mock.MagicMock(
                return_value={'A': '1', 'B': 'a \' % $2'}
            )
            result = self.runner.invoke(
                get,
                [
                    '--s3-path',
                    'myev-tests-123/dummy',
                    'B'
                ]
            )

            self.assertEqual(result.output, 'B=\'a \'"\'"\' % $2\'\n')
            mock_storage.assert_called_once_with(
                kms_alias=None,
                region=None
            )
            mock_get.assert_called_once_with(s3_path='myev-tests-123/dummy')
            self.assertEqual(result.exit_code, 0)

    @mock_kms
    @mock_s3
    def test_get_all(self):
        with mock.patch('myev.main.EnvironmentStorage') as mock_storage:
            mock_get = mock_storage.return_value.get = mock.MagicMock(
                return_value={'A': '1', 'B': 'test', 'C': 'test2'}
            )
            result = self.runner.invoke(
                get,
                [
                    '--s3-path',
                    'myev-tests-123/dummy'
                ]
            )

            self.assertEqual(result.output, 'A=1\nC=test2\nB=test\n')
            mock_storage.assert_called_once_with(
                kms_alias=None,
                region=None
            )
            mock_get.assert_called_once_with(s3_path='myev-tests-123/dummy')
            self.assertEqual(result.exit_code, 0)
