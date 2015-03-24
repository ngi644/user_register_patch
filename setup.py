# encoding: utf-8

"""
Created by nagai at 15/03/23
"""

from setuptools import setup, find_packages
__author__ = 'nagai'


setup(
    name='userregisterpatch',
    description='Monky patch for create account method on Open edx',
    author='Takashi Nagai',
    author_email='ngi644@gmail.com',
    url='',
    version='0.2.0',
    license='AGPL-3.0',
    keywords=['openedx',],
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
    ],
    classifiers=[
        # https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Education',
        'Topic :: Internet :: WWW/HTTP',
    ],
)

