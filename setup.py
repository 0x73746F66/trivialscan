import os
import pathlib
from setuptools import setup, find_packages

setup(
    name="tls-verify",
    version="0.1.4",
    author='Christopher Langton',
    author_email='chris@langton.cloud',
    description="Validate the security of your TLS connections so that they deserve your trust.",
    long_description=pathlib.Path(os.path.join(os.path.dirname(__file__), "README.md")).read_text(),
    long_description_content_type="text/markdown",
    url="https://gitlab.com/chrislangton/py-tls-veryify",
    project_urls={
        "Git": "https://gitlab.com/chrislangton/py-tls-veryify",
    },
    classifiers=[
        "Operating System :: OS Independent",
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    include_package_data=True,
    install_requires=[
        'certifi==2021.5.30',
        'cryptography==35.0.0',
        'asn1crypto==1.4.0',
        'certvalidator==0.11.1',
        'oscrypto==1.2.1',
        'pyOpenSSL==21.0.0',
        'validators==0.18.2',
        'idna==3.2',
        'tabulate==0.8.9'
    ],
    entry_points = {
        'console_scripts': ['tlsverify=tlsverify.cli:main'],
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    options={"bdist_wheel": {"universal": "1"}},
)
