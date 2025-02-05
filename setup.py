from setuptools import setup, find_packages

setup(
    name="traffic_statistics",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'tabulate>=0.9.0',
        'argparse>=1.4.0',
        'pyshark>=0.6.0',
        'scapy>=2.5.0',
    ],
)