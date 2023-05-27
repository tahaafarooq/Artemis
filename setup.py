from os import path
from setuptools import setup

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="artemis",
    version="1.0",
    description="A community package-based API security framework that simplifies carrying out scans, and pentests upon certain scope while performing security penetration testing and researches.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tahaafarooq/Artemis",
    download_url="",
    author="Tahaa Farooq",
    author_email="tahacodez@gmail.com",
    license="MIT",
    packages=["artemis"],
    keywords=[
        "Artemis API",
        "Penetration Testing" "VAPT" "Scanner" "Scanning" "Vunlerability" "Pentesting" "Pentest API",
        "python-tanzania",
    ],
    install_requires=["vulners", "requests", "python-dotenv", "python-wappalyzer", "wappalyzer"],
    include_package_data=True,
    python_requires=">=3.7",
    classifiers=[
        "Intended Audience :: Security Researchers"
        "Topic :: Penetration Testing Tools :: Security Tools",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
    ],
)