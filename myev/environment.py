#!/usr/bin/env python
import json
import logging
import sys
import traceback
from logging import StreamHandler, Formatter

import botocore

from myev.utils import is_valid_environment_variable_name, to_json
from myev.encryption import S3EncryptionClient, KMSClient
from myev.errors import (
    ConfigurationFileNotFoundError,
    ConfigurationInvalidEnvironmentVariableNameError
)


module_logger = logging.getLogger(__name__)


class EnvironmentStorage(object):
    def __init__(self, kms_alias, region=None, display=None, stream=None):
        stream = stream or sys.stderr
        logger = display or module_logger
        self._logger = logger

        # If no display is provided, the module_logger is configured and used.
        if isinstance(self._logger, logging.Logger):
            self._configure_logger(stream=stream)

        self._encryption_backend = S3EncryptionClient(
            key_provider=KMSClient(alias=kms_alias, region=region)
        )

    def _configure_logger(self, stream):
        self._logger.setLevel(logging.INFO)
        self._handler = StreamHandler(stream=stream)
        self._handler.setLevel(logging.INFO)
        self._format = \
            '[%(asctime)s]\t%(levelname)s\t%(message)s'
        self._formatter = Formatter(fmt=self._format)
        self._handler.setFormatter(self._formatter)
        self._logger.addHandler(self._handler)

    def _output(self, message, level):
        levels = {'debug': 10, 'info': 20, 'warn': 30, 'error': 40}
        if isinstance(self._logger, logging.Logger):
            self._logger.log(msg=message, level=levels[level])
        else:
            if level == 'error':
                self._logger.failed(message)
            else:
                self._logger.info(message)

    def _normalize_environment_variables(self, name_value_pairs):
        # Check if variable names are valid and convert names to uppercase.
        variables = {}
        for name, value in name_value_pairs.items():
            if not is_valid_environment_variable_name(name):
                raise ConfigurationInvalidEnvironmentVariableNameError(
                    "Variable name '{}' is not a valid '"
                    "environment variable name".format(name)
                )
            if not name.isupper():
                self._output(
                    "Converting variable name '{}' to upper case.".format(
                        name
                    ),
                    'warn'
                )
            variables[name.upper()] = value
        return variables

    def add(self, s3_path, variables):
        """
        Create or update the given configuration file.
        :param str s3_path: the S3 bucket/key path (e.g. s3://bucket/key)
        :param dict[str] variables: dictionary of variable name-value pairs
        """

        bucket, s3_key = self._encryption_backend.s3_path_split(s3_path)
        variables = self._normalize_environment_variables(variables)

        # If UPDATING the try is executed, if CREATING a new env, the except is.
        try:
            environment = self.get(s3_path)
            environment.update(variables)
            self._output(
                'Object {} exists. Adding/Updating variables {}.'.format(
                    s3_path,
                    ','.join(variables.keys())),
                'info'
            )
            environment = environment
        except ConfigurationFileNotFoundError:
            self._output(
                'Object {} does not exist. Creating with variables {}.'.format(
                    s3_path,
                    ','.join(variables.keys())
                ),
                'info')
            environment = variables

        self._encryption_backend.put_object(
            bucket=bucket,
            key=s3_key,
            body=to_json(environment)
        )

        return environment

    def get(self, s3_path):
        bucket, s3_key = self._encryption_backend.s3_path_split(s3_path)

        try:
            s3_object = self._encryption_backend.get_object(
                bucket=bucket,
                key=s3_key
            )
        except botocore.exceptions.ClientError:
            self._output(
                'S3 error: check if the given S3 Path exists '
                '(Bucket={}, Key={}).'.format(bucket, s3_key),
                'error'
            )
            self._output(traceback.format_exc().splitlines()[-1], 'error')
            raise ConfigurationFileNotFoundError(
                'S3 path not found: {}'.format(s3_path)
            )

        return json.loads(s3_object['Body'])

    def delete(self, s3_path, variables):

        bucket, s3_key = self._encryption_backend.s3_path_split(s3_path)

        environment = self.get(s3_path)

        self._output(
            "Current Key Alias: '{}'".format(
                self._encryption_backend.key_provider.alias
            ),
            'info'
        )

        for name in variables:
            try:
                del environment[name]
                self._output(
                    'Deleted environment variable {}'.format(name),
                    'info'
                )
            except KeyError:
                self._output(
                    'No environment variable named {}'.format(name),
                    'warn'
                )

        self._encryption_backend.put_object(
            bucket=bucket,
            key=s3_key,
            body=to_json(environment)
        )

        return environment
