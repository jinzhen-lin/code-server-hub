# encoding: utf8
from setuptools import setup

setup(
    name="code_server_hub",
    version="1.0.0",
    include_package_data=True,
    description="A multi-user server for code-server",
    author="Jinzhen Lin",
    author_email="linjinzhen@hotmail.com",
    url="https://github.com/jinzhen-lin/code_server_hub",
    license="BSD",
    python_requires=">=3.6",
    install_requires=[
        "tornado>=5.1",
        "jupyterhub>=1.0.0",
        "simplepam>=0.1.5",
    ],
    packages=["code_server_hub"],
    entry_points={
        "console_scripts": [
            "code-server-hub = code_server_hub.app:main",
        ],
    },
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Software Development :: Libraries",
        "Topic :: Utilities"
    ]
)
