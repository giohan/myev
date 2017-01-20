from __future__ import absolute_import
import string
import random
import os
from StringIO import StringIO
import unittest

import mock

from myev.utils import pkcs5_pad, pkcs5_unpad, to_base64, to_json
from myev.utils import is_valid_environment_variable_name
from myev.utils import parse_environment_variable_name_value_pairs


# Do not allow access to AWS even if mocking is not present.
os.environ['AWS_ACCESS_KEY_ID'] = 'TEST'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'TEST'


class TestUtilities(unittest.TestCase):
    def test_pkcs5_pad(self):
        for block_size in (16, 32, 64):
            for _ in xrange(50):
                length = random.randint(1, 100)
                a = ''.join(
                    random.choice(string.ascii_lowercase)
                    for _ in xrange(length + 1)
                )
                a = pkcs5_pad(a, block_size=block_size)
                self.assertEqual(
                    0,
                    len(a) % block_size
                )

    def test_pkcs5_unpad(self):
        sample = 'a' + chr(5) * 5
        self.assertEqual(pkcs5_unpad(sample), 'a')

    def test_to_base64(self):
        from base64 import b64encode

        # We are only interested in ASCII strings.
        self.assertEqual(
            to_base64('this is a test'),
            b64encode('this is a test')
        )

    def test_to_json(self):
        self.assertEqual(
            to_json({'a': 1, 'b': 2}),
            '{"a":1,"b":2}'
        )

    def test_is_environment_variable_name_valid(self):
        self.assertFalse(is_valid_environment_variable_name('0ABCD'))
        self.assertFalse(is_valid_environment_variable_name('A BCD'))
        self.assertFalse(is_valid_environment_variable_name('A=BCD'))

        self.assertTrue(is_valid_environment_variable_name('_a_b_c_1'))
        self.assertTrue(is_valid_environment_variable_name('__a_b_c_1'))
        self.assertTrue(is_valid_environment_variable_name('A_10303'))

    def test_parse_environment_variable_name_value_pairs(self):
        from myev.errors import \
            ConfigurationInvalidEnvironmentVariableNameError

        test_cases = (
            ("A=1 B=2", {'A': '1', 'B': '2'}),
            ("A=1 B='2'", {'A': '1', 'B': '2'}),
            ("A=1 B='2 3'", {'A': '1', 'B': '2 3'}),
            ("A=1 B='2=3'", {'A': '1', 'B': '2=3'}),
            # Issue #17
            (
                "JAVA_OPTS="
                "'-XX:+UseCompressedOops -XX:-OmitStackTraceInFastThrow'",
                {
                    'JAVA_OPTS':
                    '-XX:+UseCompressedOops -XX:-OmitStackTraceInFastThrow'
                }
            )
        )

        # Read from STDIN
        for environment_string, expected in test_cases:
            mock_standard_input = StringIO(environment_string)
            with mock.patch('sys.stdin', StringIO(environment_string)):
                self.assertEqual(
                    mock_standard_input.getvalue(),
                    environment_string
                )
                result = parse_environment_variable_name_value_pairs(None)
                self.assertEqual(result, expected)

        # Read from function parameter
        success_cases = (
            ('A=1', {'A': '1'}),
             ("B='2 3'", {'B': '2 3'})
        )

        for environment_string, expected in success_cases:
            self.assertEqual(
                expected,
                parse_environment_variable_name_value_pairs(environment_string)
            )

        failure_cases = (
            'A B=2',
            'A B=2 =',
            "A-=1 B'2 aaa='"
        )

        exc_class = ConfigurationInvalidEnvironmentVariableNameError
        for failure_case in failure_cases:
            with self.assertRaises(excClass=exc_class):
                parse_environment_variable_name_value_pairs(
                    failure_case
                )
