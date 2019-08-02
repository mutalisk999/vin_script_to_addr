#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'mutalisk'

from setuptools import setup

require_packages = ['setuptools', 'base58', 'cashaddress']

setup(name='vin_script_to_addr',
      version='0.1.0',
      description='calculate address from vin script for bitcoin-like coins',
      author='',
      author_email='',
      url='https://github.com/mutalisk999/vin_script_to_addr',
      platforms='any',
      packages=['vin_script_to_addr'],
      install_requires=require_packages,
      zip_safe=False,)