# Azul Plugin Portex

Static malware analysis of PE files with a focus on malformation robustness and anomaly detection.

## Installation

```bash
pip install azul-portex
```

To install azul-plugin-portex for development run the command
(from the root directory of this project):

```bash
pip install -e .
```
You will also need to install the portex binary using the command `./install-portex.sh`
This is a bash script installing a binary so you should check the script first.

## Usage

Usage on local files:

```bash
$ azul-plugin-portex malware.file
... example output goes here ...
```

this plugin runs Portex on PE files

Usage on local files:

```
azul-plugin-portex path/to/file.exe
```

Example Output:

```
COMPLETED

events (1)

event for 72805063ab7465bc5624cd73c625abad0bfd7e8c7c39a1f13d0bdfb5a8a420b9:None
  {}
  output data streams (2):
    34555 bytes - EventData(hash='a4820e3513deadb92a5064e44605f1794826ddba83e19587873bb4ad0331c50e', label='report')
    50902 bytes - EventData(hash='562afd87b3c0162b91fba360d3e8e863cd67c93d0c4075510ba31049fd28e5fc', label='safe_png')
  output features:
    portex_anomalies: portex_anomaly - COFF Header: Time date stamp is too far in the past
                      portex_anomaly - Deprecated Characteristic in COFF File Header: IMAGE_FILE_LINE_NUMS_STRIPPED
                      portex_anomaly - Deprecated Characteristic in COFF File Header: IMAGE_FILE_LOCAL_SYMS_STRIPPED
                      portex_anomaly - Import function typical for injection/unpacking: CreateProcessA creates a process (check if SUSPENDED flag is used)
                      portex_anomaly - Import function typical for injection/unpacking: CreateThread is used to open and execute a thread in the victim process
                      portex_anomaly - Import function typical for injection/unpacking: GetProcAddress dynamically resolves imports
                      portex_anomaly - Import function typical for injection/unpacking: LoadLibraryA maps module into the address space of the calling process or dynamically resolves imports
                      portex_anomaly - Import function typical for injection/unpacking: WinExec runs the specified application
                      portex_anomaly - Imports are fractionated! Affected import DLLs: ole32.DLL, OLEAUT32.DLL, WININET.DLL, KERNEL32.DLL, USER32.DLL, GDI32.DLL, ADVAPI32.DLL, CRTDLL.DLL, MSVCRT.DLL, glu32.dll, avifil32.dll
                      portex_anomaly - Optional Header: size of code is too small (0x8000), it should be 0xac00
                      portex_anomaly - Optional Header: size of initialized data is too small (0x4200), it should be 0x9e00
                      portex_anomaly - Optional Header: size of uninitialized data is too large (0x21400), it should be 0x0
                      portex_anomaly - Section 1 with name .text has write and execute characteristics.
                      portex_anomaly - Section 6 with name .l1 has write and execute characteristics.
                      portex_anomaly - Section Header 1 with name .text has unusual characteristics, that shouldn't be there: Write
                      portex_anomaly - Section Header 1 with name .text: SIZE_OF_RAW_DATA (32460) must be a multiple of File Alignment (512)
                      portex_anomaly - Section Header 10 with name .idata should (but doesn't) contain the characteristics: Write
                      portex_anomaly - Section Header 11 with name .idata should (but doesn't) contain the characteristics: Write
                      portex_anomaly - Section Header 12 with name .data has unusual characteristics, that shouldn't be there: Discardable
                      portex_anomaly - Section Header 12 with name .data should (but doesn't) contain the characteristics: Write
                      portex_anomaly - Section Header 13 with name .rsrc has unusual characteristics, that shouldn't be there: Discardable
                      portex_anomaly - Section Header 2 with name .rdata has unusual characteristics, that shouldn't be there: Uninitialized Data, Write
                      portex_anomaly - Section Header 2 with name .rdata should (but doesn't) contain the characteristics: Initialized Data
                      portex_anomaly - Section Header 2 with name .rdata: SIZE_OF_RAW_DATA is 0
                      portex_anomaly - Section Header 3 with name .rsrc has unusual characteristics, that shouldn't be there: Write
                      portex_anomaly - Section Header 3 with name .rsrc: SIZE_OF_RAW_DATA (12752) must be a multiple of File Alignment (512)
                      portex_anomaly - Section Header 4 with name .idata has unusual characteristics, that shouldn't be there: Code
                      portex_anomaly - Section Header 4 with name .idata: SIZE_OF_RAW_DATA (3748) must be a multiple of File Alignment (512)
                      portex_anomaly - Section Header 7 with name .text has unusual characteristics, that shouldn't be there: Initialized Data, Shared
                      portex_anomaly - Section Header 7 with name .text should (but doesn't) contain the characteristics: Code, Execute
                      portex_anomaly - Section Header 8 with name .idata should (but doesn't) contain the characteristics: Write
                      portex_anomaly - Section Header 9 with name .rsrc has unusual characteristics, that shouldn't be there: Code, Execute
                      portex_anomaly - Section Header 9 with name .rsrc should (but doesn't) contain the characteristics: Initialized Data
                      portex_anomaly - Section name is unusual: .kofbl
                      portex_anomaly - Section name is unusual: .l1

Feature key:
  portex_anomalies:  Anomalies flagged by portex

```

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
