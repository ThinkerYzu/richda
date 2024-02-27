#-----------------------------------------------------------------------------
# richda: setup.py
#
# Setup/installation script.
#
# K.F. Lee <thinker.li@gmail.com>
#-----------------------------------------------------------------------------
import os, sys
from setuptools import setup


try:
    with open('README.md', 'rt') as readme:
        description = '\n' + readme.read()
except IOError:
    # maybe running setup.py from some other dir
    description = ''


setup(
    # metadata
    name='richda',
    description='Disassembler with rich information.',
    long_description=description,
    license='BSD',
    version='0.1',
    author='K.F. Lee',
    maintainer='K.F. Lee',
    author_email='thinker.li@gmail.com',
    url='https://github.com/ThinkerYzu/richda',
    platforms='Cross Platform',
    classifiers = [
        'Programming Language :: Python :: 3',
        ],
    install_requires=["pyelftools >= 0.30", "capstone >= 5.0.1"],
    scripts=['scripts/richda.py'],
)
