#!/usr/bin/env python
from functools import wraps
import os
from pipes import quote
from traceback import format_exc

import click
from myev.environment import EnvironmentStorage

from myev.errors import ConfigurationFileNotFoundError, KMSAliasNotFoundError
from myev.utils import parse_environment_variable_name_value_pairs


def exception_handler(fn):
    """
    Exception handler for CLI actions.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            message = '{}: {}'.format(
                e.__class__.__name__,
                e.message
            )
            if os.environ.get('MYEV_DEBUG') is not None:
                click.echo(format_exc(), err=True)
            raise click.ClickException(message)
    return wrapper


@click.group()
@click.version_option()
def cli():
    """Manage environment variables for docker containers"""
    pass


@cli.command('set', help='Set or update environment variables.')
@click.option('--s3-path', required=True,
              help='The S3 path in the format: s3://bucket/key')
@click.option('--kms-alias', required=False)
@click.option('--region', envvar='AWS_DEFAULT_REGION')
@click.argument('variables', required=False, nargs=-1)
@exception_handler
def add(s3_path, kms_alias, region, variables):
    """
    Set/Update environment variables.
    :param str s3_path: The full path where the env file is located.
    :param str kms_alias: Alias of the KMS key to be used.
    :param str region: AWS Region for KMS and S3.
    :param str variables: Environment variable name-value pairs to add/update.
    """
    # If no variables were given on the command-line, read from STDIN.
    if not variables:
        parsed_variables = parse_environment_variable_name_value_pairs(None)
    else:
        parsed_variables = {}
        for name_value_pair in variables:
            parsed_variables.update(
                parse_environment_variable_name_value_pairs(name_value_pair)
            )

    environment_storage = EnvironmentStorage(
        kms_alias=kms_alias,
        region=region
    )

    try:
        environment_storage.add(
            s3_path=s3_path,
            variables=parsed_variables
        )
    except KMSAliasNotFoundError as e:
        if e.message.endswith(': None'):
            message = \
                'Configuration file does not exist. For initialization ' \
                'please provide the KMS alias using the ' \
                '--kms-alias parameter ({}).'.format(e.message)
        else:
            message = 'Invalid KMS alias: {}'.format(e.message)
        raise click.ClickException(message)


@cli.command(help='Get one or many environment variables.')
@click.option('--s3-path', required=True,
              help='The S3 path in the format: s3://bucket/key')
@click.option('--region', envvar='AWS_DEFAULT_REGION', help='AWS region')
@click.argument('variable_names', required=False, nargs=-1)
@exception_handler
def get(s3_path, region, variable_names):
    """
    Get one or many environment variables.
    :param str s3_path: The full path where the env file is located.
    :param str region: AWS Region for KMS and S3.
    :param (str,) variable_names: Which variables to display. If none is
    provided, all are displayed.
    """
    environment_storage = EnvironmentStorage(
        kms_alias=None,
        region=region
    )

    try:
        stored_variables = environment_storage.get(
            s3_path=s3_path
        )
    except ConfigurationFileNotFoundError:
        raise click.Abort(
            "Access denied or S3 path does not exist: '{}'".format(
                s3_path
            )
        )

    # Print all configuration if no variables are given
    if not variable_names:
        variable_names = stored_variables.keys()

    for name in variable_names:
        try:
            # The default log stream is STDERR, so by printing environment
            # variables in STDOUT we can easily redirect all logs
            # and read only variables.
            click.echo(
                '{}={}'.format(
                    quote(name),
                    quote(stored_variables[name])
                )
            )
        except KeyError:
            raise click.Abort(
                "No environment variable named '{}'.".format(
                    name
                )
            )


@cli.command(help='Remove one or multiple environment variables.')
@click.option('--s3-path', required=True,
              help='The S3 path in the format: s3://bucket/key')
@click.option('--region', envvar='AWS_DEFAULT_REGION')
@click.option('--prompt/--no-prompt', default=True)
@click.argument('variables', nargs=-1)
@exception_handler
def delete(s3_path, region, variables, prompt):
    """
    Remove environment variables.
    :param str s3_path: The full path where the env file is located.
    :param str kms_alias: Alias of the KMS key to be used.
    :param str variables: Which env variables to delete.
    :param str region: Region of the KMS-key.
    :param bool prompt: whether to prompt for confirmation or not before
    deleting the variables.
    """
    environment_storage = EnvironmentStorage(
        kms_alias=None,
        region=region
    )

    if not variables:
        raise click.Abort('No variables given for deletion.')

    if not prompt or click.confirm(
            "Are you sure you want to delete the variables '{}'?".format(
                ', '.join(variables)
            ),
            abort=True
    ):
        environment_storage.delete(
            s3_path=s3_path,
            variables=variables
        )


@cli.command(help='Rotate KMS encryption keys.', name='rotate-keys')
@click.option('--s3-path', required=True,
              help='The S3 path in the format: s3://bucket/key')
@click.option('--region', envvar='AWS_DEFAULT_REGION')
@click.option('--new-kms-alias', required=True)
@exception_handler
def rotate_keys(s3_path, region, new_kms_alias):
    # Untested
    environment_storage = EnvironmentStorage(
        kms_alias=None,
        region=region
    )
    variables = environment_storage.get(s3_path)

    environment_storage = EnvironmentStorage(
        kms_alias=new_kms_alias,
        region=region
    )
    environment_storage.add(s3_path, variables)
    click.echo(
        "KMS Key for '{}' updated to '{}'.".format(
            s3_path,
            new_kms_alias
        )
    )


if __name__ == '__main__':
    cli()
