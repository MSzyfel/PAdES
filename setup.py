from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="PAdES",
    version="1.0.0",
    author="",
    author_email="",
    description="A tool for emulating a qualified electronic signature according to the PAdES standard (PDF Advanced Electronic Signature).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MSzyfel/PAdES",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "key-generator=key_generator.main:main",
            "pdf-signer=pdf_signer.main:main",
        ],
    },
)

