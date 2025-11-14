from setuptools import setup, find_packages

setup(
    name="dpqc",
    version="0.0.1",
    description="DPQC - Developer's PQC (Post-Quantum Cryptography) Library",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="QudsLab",
    author_email="QudsLab@proton.me",
    url="https://github.com/QudsLab/dpqc",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "termcolor>=1.1.0"
    ],
    python_requires=">=3.7",
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords=["post-quantum", "cryptography", "pqc", "quantum-safe", "ml-kem", "ml-dsa", "falcon"],
    project_urls={
        "Homepage": "https://github.com/QudsLab/dpqc",
        "Repository": "https://github.com/QudsLab/dpqc",
        "Issues": "https://github.com/QudsLab/dpqc/issues",
    },
)
