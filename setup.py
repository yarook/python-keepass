import sys
from setuptools import setup

setup(name='keepass',
      version='1.0',
      description='Python interface to KeePass file format v3 (used in KeePass V1.x and KeePassX)',
      author='Brett Viren',
      author_email='brett.viren@gmail.com',
      url='https://github.com/brettviren/python-keepass',
      packages=['keepass'],
      entry_points=dict(console_scripts=['keepass=keepass.cli:main', 'keepass-%s=keepass.cli:main' % sys.version[:3]]),
     )
