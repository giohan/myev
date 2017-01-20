from setuptools import setup, find_packages

setup(
    name='myev',
    version='0.0.1',
    packages=find_packages(exclude=("tests", "tests.*")),
    extras_require={
        "test": [
            "mock",
            "pytest",
            "moto"
        ]
    },
    install_requires=[
        "click==6.6",
        "boto3==1.4.1",
        "botocore==1.4.60",
        "pycrypto==2.6.1"
    ],
    entry_points='''
        [console_scripts]
        myev=myev.main:cli
    ''',
)
