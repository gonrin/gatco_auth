# -*- coding: utf-8 -*-
import re
from os import path
from setuptools import find_packages, setup

ROOT_DIR = path.abspath(path.dirname(__file__))

DESCRIPTION = 'Gatco-Auth - Authentication for Gatco'
LONG_DESCRIPTION = open(path.join(ROOT_DIR, 'README.rst')).read()
VERSION = re.search(
    "__version__ = '([^']+)'",
    open(path.join(ROOT_DIR, 'gatco_auth', '__init__.py')).read()
).group(1)


setup(
    name='Gatco-Auth',
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    url='https://github.com/gonrin/gatco_auth/',
    author='cuongnc.coder and contributors',
    author_email='cuongnc.coder@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    packages=find_packages(exclude=['tests*']),
    include_package_data=True,
    install_requires=[
        'sanic', 'passlib'
    ],
    extras_require={
        'dev': [
            'aiohttp',
            'flake8',
            'pytest',
            'pytest-cov',
            'Sphinx',
            'tox',
            'twine',
        ],
    },
    zip_safe=False,
    platforms='any',
)
