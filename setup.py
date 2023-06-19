from setuptools import setup, find_packages

setup(
    name='XMLchain',
    version='0.1',
    packages=find_packages(),
    url='',
    license='MIT',
    author='Your Name',
    author_email='Your Email',
    description='A Python package for creating, verifying, and updating blockchainified XML files.',
    install_requires=[
        'pycryptodome',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
)
