from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file.
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='sequoia',
    version='0.1.0', # XXX parse
    description='Python bindings for the Sequoia PGP library.',
    long_description=long_description,
    url='https://sequoia-pgp.org/',
    author='The Sequoia Contributors',
    author_email='devel@sequoia-pgp.org',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='OpenPGP PGP GnuPG',

    packages=['sequoia'],

    setup_requires=["cffi>=1.0.0", "pytest-runner"],
    cffi_modules=["sequoia/sequoia_build.py:ffibuilder"],
    install_requires=["cffi>=1.0.0"],
    tests_require=["pytest"],
)
