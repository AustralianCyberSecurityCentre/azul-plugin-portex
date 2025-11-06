"""Test cases for plugin output."""

import json
import subprocess
from unittest import mock

from azul_runner import FV, Event, EventData, JobResult, State, test_template

from azul_plugin_portex.main import AzulPluginPortex


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginPortex

    def get_hash(self, result):
        hash = ""
        for event in result.events:
            for event_data in event.data:
                if event_data.label == "text":
                    hash = event_data.hash

        return hash

    def test_windows_executable_empty_features(self):
        """Test for binary that produces no portex features."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "0423e10a674fb7e96557eac50b51207709a248df6e06aeeba401ded6157c1298",
                        "Malicious Windows 32EXE, spreader.",
                    ),
                )
            ],
        )
        changing_hash = self.get_hash(result)
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="0423e10a674fb7e96557eac50b51207709a248df6e06aeeba401ded6157c1298",
                        data=[
                            EventData(hash=f"{changing_hash}", label="report"),
                            EventData(
                                hash="4808bda7fb20a50850b6c957b4e70b2541fd5d2c681220564277bc948720e9c1",
                                label="safe_png",
                            ),
                        ],
                    )
                ],
                data={
                    f"{changing_hash}": b"",
                    "4808bda7fb20a50850b6c957b4e70b2541fd5d2c681220564277bc948720e9c1": b"",
                },
            ),
        )

    def test_windows_executable_peidSigs(self):
        """Test for binary that produces peid signatures."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "b1a714ed39fd6c259638c2c21a8eccbb548f16ca385691039db713ceabea3b07",
                        "Windows dll32 with peid signatures.",
                    ),
                )
            ],
        )
        changing_hash = self.get_hash(result)
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="b1a714ed39fd6c259638c2c21a8eccbb548f16ca385691039db713ceabea3b07",
                        data=[
                            EventData(hash=f"{changing_hash}", label="text"),
                            EventData(
                                hash="47e2231316e38f244c9692e82b64e6b9ac24fef9d00ca77ebc66aa8bc098745b",
                                label="safe_png",
                            ),
                        ],
                        features={
                            "peid_signatures": [
                                FV(
                                    "[Microsoft Visual C# v7.0 / Basic .NET] bytes matched: 54 at address: 0x2aae pattern:  ff 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                                )
                            ],
                            "portex_anomalies": [
                                FV(
                                    "Optional Header: The default image base for a DLL is 0x10000000, but actual value is 0x400000"
                                )
                            ],
                        },
                    )
                ],
                data={
                    f"{changing_hash}": b"",
                    "47e2231316e38f244c9692e82b64e6b9ac24fef9d00ca77ebc66aa8bc098745b": b"",
                },
            ),
        )

    def test_windows_executable_anomalies(self):
        """Test for binary that produces anomalies."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "9f43daa2e91d3c2698e41493a257b1f35a5d36299a294ab792b93132ee4f0dee", "Windows 32EXE."
                    ),
                )
            ],
        )
        changing_hash = self.get_hash(result)
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="9f43daa2e91d3c2698e41493a257b1f35a5d36299a294ab792b93132ee4f0dee",
                        data=[
                            EventData(hash=f"{changing_hash}", label="text"),
                            EventData(
                                hash="039cd2a319534637793452a9113996710403384b488c3401af44875f727e701b",
                                label="safe_png",
                            ),
                        ],
                        features={
                            "portex_anomalies": [
                                FV("Deprecated Characteristic in COFF File Header: IMAGE_FILE_LINE_NUMS_STRIPPED"),
                                FV("Deprecated Characteristic in COFF File Header: IMAGE_FILE_LOCAL_SYMS_STRIPPED"),
                                FV(
                                    "Import function typical for injection/unpacking: CreateProcessA creates a process (check if SUSPENDED flag is used)"
                                ),
                                FV(
                                    "Import function typical for injection/unpacking: CreateThread is used to open and execute a thread in the victim process"
                                ),
                                FV(
                                    "Import function typical for injection/unpacking: CreateToolhelp32Snapshot used to iterate processes"
                                ),
                                FV(
                                    "Import function typical for injection/unpacking: FindResourceA used to find and load data from resources"
                                ),
                                FV(
                                    "Import function typical for injection/unpacking: GetProcAddress dynamically resolves imports"
                                ),
                                FV(
                                    "Import function typical for injection/unpacking: LoadLibraryA maps module into the address space of the calling process or dynamically resolves imports"
                                ),
                                FV(
                                    "Import function typical for injection/unpacking: LoadResource used to find and load data from resources"
                                ),
                                FV(
                                    "Import function typical for injection/unpacking: Process32First used to iterate processes"
                                ),
                                FV(
                                    "Import function typical for injection/unpacking: Process32Next used to iterate processes"
                                ),
                                FV(
                                    "Import function typical for injection/unpacking: SizeofResource used to find and load data from resources"
                                ),
                                FV("Import function typical for injection/unpacking: VirtualAlloc allocates memory"),
                                FV(
                                    "Import function typical for injection/unpacking: VirtualProtect may set PAGE_EXECUTE for memory region"
                                ),
                                FV("Optional Header: Size of Headers should be 0x600, but is 0x1000"),
                                FV("Optional Header: size of code is too large (0x21000), it should be 0x20c00"),
                                FV(
                                    "Section Header 4 with name .rdata has unusual characteristics, that shouldn't be there: Shared"
                                ),
                                FV(
                                    "Section Header 5 with name .idata should (but doesn't) contain the characteristics: Write"
                                ),
                                FV(
                                    "Section Header 8 with name .reloc has unusual characteristics, that shouldn't be there: Shared"
                                ),
                                FV(
                                    "Section Header 8 with name .reloc should (but doesn't) contain the characteristics: Discardable"
                                ),
                            ]
                        },
                    )
                ],
                data={
                    f"{changing_hash}": b"",
                    "039cd2a319534637793452a9113996710403384b488c3401af44875f727e701b": b"",
                },
            ),
        )

    @mock.patch("subprocess.run")
    def test_exception_in_portex(self, subprocess_mock):
        """Test that subprocess exception is firing correctly."""
        mock_process = mock.MagicMock()
        attrs = {"communicate.side_effect": subprocess.CalledProcessError}
        mock_process.configure_mock(**attrs)
        subprocess_mock.return_value = mock_process
        state = AzulPluginPortex.run_portex("/a/randomFilePath", "/a/randomReportPath", "a/randomImagePath")
        expected_message = "Error running Portex subprocess. Reason"
        self.assertTrue(expected_message in state.message)

    def test_nonascii_stripped(self):
        """Test that when a portex report has non-ascii characters they are correctly
        removed to leave only standard text in the report (this helps with rendering on the UI)."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "869892207ed85b20322249ae956d05a5b9daa7817c0e621ab0abd68fb4588c23", "Malicious non ascii."
                    ),
                )
            ],
        )
        changing_hash = self.get_hash(result)
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="869892207ed85b20322249ae956d05a5b9daa7817c0e621ab0abd68fb4588c23",
                        data=[
                            EventData(hash=f"{changing_hash}", label="report"),
                            EventData(
                                hash="f79aa5ddf164ed25f4c8a720e8b566cf6a325a53efcb687d940a00f7a7055146",
                                label="safe_png",
                            ),
                        ],
                        features={"portex_anomalies": [FV("COFF Header: Time date stamp is in the future")]},
                    )
                ],
                data={
                    f"{changing_hash}": b"",
                    "f79aa5ddf164ed25f4c8a720e8b566cf6a325a53efcb687d940a00f7a7055146": b"",
                },
            ),
        )
