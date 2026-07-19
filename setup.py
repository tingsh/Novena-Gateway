from setuptools import setup, find_packages

from novena_gateway.__version__ import __version__

setup(
    name="novena-gateway",
    version=__version__,
    description="Novena Gateway IoT Gateway — Industrial protocol gateway for Novena Hub",
    author="Novena",
    packages=find_packages(),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "novena-gateway=novena_gateway.main:main",
        ],
    },
    install_requires=[
        "PyYAML",
        "simplejson",
        "orjson",
        "pybase64",
        "jsonpath-rw",
        "regex",
        "packaging>=23.1",
        "cachetools",
        "python-dateutil",
        "psutil",
        "cryptography",
        "PySocks",
        "paho-mqtt>=1.6.0",
        "pymodbus==3.8.0",
        "pyserial",
        "pyserial-asyncio",
    ],
)
