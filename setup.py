import pathlib
from setuptools import setup, find_packages

long_description = pathlib.Path('README.md').read_text()
requirements = pathlib.Path('requirements.txt')
install_requires = []
for line in requirements.read_text().splitlines():
    req = line.strip()
    if req.startswith('#'):
        continue
    install_requires.append(req)

setup(
    name="tls-verify",
    version="0.0.1",
    author='Christopher Langton',
    author_email='chris@langton.cloud',
    description="Because; of course it is",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/chrislangton/py-tls-veryify",
    project_urls={
        "Git": "https://gitlab.com/chrislangton/py-tls-veryify",
    },
    classifiers=[
        "Operating System :: OS Independent",
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        "License :: OSI Approved :: MIT License",
    ],
    include_package_data=True,
    install_requires=install_requires,
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    options={"bdist_wheel": {"universal": "1"}},
)
