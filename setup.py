from distutils.core import setup
from justifycert import __identify__

ident = __identify__.Identity()

setup(
    name=ident.name,
    version=ident.version,
    author=ident.author,
    author_email=ident.author_email,
    url=ident.url,
    packages=['',],
    license=ident.license,
    long_description=open('README.md').read(),
    classifiers=(
            'Development Status :: 2 - Pre-Alpha',
            'Intended Audience :: Developers',
            'Natural Language :: English',
            'License :: OSI Approved :: Apache Software License',
            'Programming Language :: Python',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6'
    ),
)

