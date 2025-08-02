from setuptools import setup

setup(
    name="netscan-cli",
    version="1.0.0",
    description="Lightweight network scanner & vuln checker",
    author="MisconfigBot",
    py_modules=["netscan"],
    install_requires=[
        "scapy==2.5.0",
        "loguru==0.7.2",
        "rich==13.7.1",
        "jinja2==3.1.4",
    ],
    entry_points={"console_scripts": ["netscan=netscan:main"]},
    python_requires=">=3.7",  # Match your README
)