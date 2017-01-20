# Myev

`Myev` is a tool that helps you **M**anage **Y**our **E**nvironment **V**ariables for ECS containers. Capabilities:
- Set/Update environment variables
- Get environment variables
- Remove environment variables
- Rotate KMS encryption keys for S3 encrypted files.

## Installation

```
git clone https://github.com/giohan/myev.git
cd myev/
virtualenv env
source env/bin/activate
pip install .

$ myev --help
Usage: myev [OPTIONS] COMMAND [ARGS]...

  Manage environment variables for docker containers

Options:
  --help  Show this message and exit.

Commands:
  get          Get one or many environment variables.
  rm           Remove one or many environment variables.
  rotate_keys  Rotate KMS encryption keys
  set          Set or update environment variables

```

## Development

### Testing

All unit tests are stored under `tests/unit`. Test cases are written using the builtin [unittest](https://docs.python.org/2/library/unittest.html).
We are using [pytest](http://docs.pytest.org/en/latest/) as a test runner.

For general mocking the [mock](https://docs.python.org/3/library/unittest.mock.html) library is used
and for AWS resource mocking the [moto](https://github.com/spulec/moto) library.

In order to install the test dependencies run in your virtual environment:

```
$ pip install .[test]
```

To run the tests you can execute:

```
$ py.test -v tests
```