#!/usr/bin/env python

from distutils.core import setup

setup(name='massexec',
    version='0.1',
    description='Mass Remote Execution',
    author='Mykhaylo Yehorov',
    author_email='yehorov@gmail.com',
    url='https://github.com/yehorov/massexec',
    license='BSD',
    long_description=open('README').read(),
    scripts=['massexec.py'],
    requires=['twisted']
    )
