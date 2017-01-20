import base64
import json
import re
import shlex

from Crypto.Cipher import AES

from myev.errors import ConfigurationInvalidEnvironmentVariableNameError


def parse_environment_variable_name_value_pairs(environment_as_string):
    """
    Parse a sequence of environment variable name-value pairs.
    :param str|None environment_as_string: the environment variable set
    as a sequence of space separated name-value pairs. Shell parsing rules
    apply. If None is passed, then the string to be parsed will be read from
    STDIN.
    :rtype: dict[str]
    """

    if environment_as_string is None:
        name_value_pairs = shlex.split(environment_as_string)
    else:
        name_value_pairs = (environment_as_string,)

    variables = {}
    for pair in name_value_pairs:
        if '=' not in pair:
            raise ConfigurationInvalidEnvironmentVariableNameError(
                "Unable to parse name-value pair: '{}'".format(pair)
            )
        name, value = pair.split('=', 1)
        # Remove single quotes
        value = ' '.join(shlex.split(value))
        if not is_valid_environment_variable_name(name):
            raise ConfigurationInvalidEnvironmentVariableNameError(
                "Unable to parse name-value pair: '{}'".format(pair)
            )
        variables[name] = value
    return variables


def to_json(obj):
    """
    Serialize the given object to JSON representation.
    Note: this function was added for compatibility on the generated JSON
    by other SDK and more specifically the Ruby AWS SDK.
    :param T obj: object to be serialized.
    :rtype: str
    """
    return json.dumps(obj, separators=(',', ':'))


def to_base64(s):
    """
    Convert the given string to base64-encoded.
    :param str s: the string to be converted.
    :rtype: str
    """
    return str(base64.b64encode(s).decode('ascii'))


def is_valid_environment_variable_name(test_string):
    """
    Check if the given string is a valid environment variable name.
    :param str test_string: the string to be checked
    :rtype: bool
    """
    validator = re.compile(r'^[a-zA-Z_]+[a-zA-Z0-9_]*$')
    return validator.match(test_string) is not None


def pkcs5_pad(s, block_size=AES.block_size):
    """
    Padding to blocksize according to PKCS #5
    calculates the number of missing chars to block_size and pads with
    ord(number of missing chars)
    @see: https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
    """
    return s + \
        (block_size - len(s) % block_size) * \
        chr(block_size - len(s) % block_size)


def pkcs5_unpad(s):
    """
    Remove padding according to PKCS #5
    """
    return s[0:-ord(s[-1])]
