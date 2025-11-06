"""Static malware analysis of PE files with a focus on malformation robustness and anomaly detection."""

import os
import subprocess  # nosec B404
import tempfile
import unicodedata
from io import BytesIO

from azul_runner import (
    BinaryPlugin,
    DataLabel,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from PIL import Image, UnidentifiedImageError

# portex is installed to the below path when it is built with the script install-portex.sh
PORTEX_PATH = "/usr/bin/portex"


class AzulPluginPortex(BinaryPlugin):
    """Static malware analysis of PE files with a focus on malformation robustness and anomaly detection."""

    VERSION = "2025.07.06"
    SETTINGS = add_settings(
        # Only windows executable (PE) files
        filter_data_types={
            "content": [
                "executable/windows/dll32",
                "executable/windows/dll64",
                "executable/windows/pe",
                "executable/windows/pe32",
                "executable/windows/pe64",
                "executable/pe32",
                "executable/dll32",
            ]
        },
    )
    FEATURES = [
        # Anomalies flagged by portex.
        Feature(name="portex_anomalies", desc="Anomalies flagged by portex", type=FeatureType.String),
        # Compilers/packers etc detected in file.
        Feature(name="peid_signatures", desc="PEID signatures found by portex", type=FeatureType.String),
    ]

    def run_portex(binary: bytes, output_path_report: str, output_path_image: str) -> State:
        """Run the portex subprocess."""
        command = ["java", "-jar", PORTEX_PATH, "-o", output_path_report, "-p", output_path_image, binary]
        # run portex subprocess
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)  # nosec B603
            if result.stderr:
                description = f"Error running Portex subprocess. Reason : {result.stderr}"
                return State(State.Label.ERROR_EXCEPTION, message=description)
        except subprocess.CalledProcessError as e:
            description = f"Error running Portex subprocess. Reason : {str(e)}"
            return State(State.Label.ERROR_EXCEPTION, message=description)
        return None

    def extract_features(self, output_file: str):
        """Extract features from Portex Report."""
        found_anomalies = False
        found_peid_sigs = False
        compilers = []
        rules = []
        with open(output_file, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    if "Anomalies" in line:
                        found_anomalies = True
                        continue
                    if found_anomalies:
                        if "* " in line:
                            anomaly = line.lstrip("* ").strip()
                            self.add_feature_values("portex_anomalies", anomaly)
                    if "PEID Signatures" in line:
                        found_peid_sigs = True
                        continue
                    if found_peid_sigs:
                        if not line.startswith("*"):
                            if "Hashes" not in line:
                                if len(compilers) == 0:
                                    compilers.append(line)
                                    continue
                                if len(compilers) % 2 != 0:
                                    rules.append(line)
                                    continue
                                if len(compilers) % 2 == 0:
                                    compilers.append(line)
                                    continue
                            else:
                                found_peid_sigs = False
            # add the two peid lines together before adding them as features
            concatenated_list = [l1.strip() + " " + l2.strip() for l1, l2 in zip(compilers, rules)]
            for feature in concatenated_list:
                self.add_feature_values("peid_signatures", feature)

    def verify_nonascii_stripped(self, output_file: str) -> State:
        """Checks for any non-ascii chars in report. Returns ERROR_EXCEPTION State if found."""
        with open(output_file, "r") as file:
            content = file.read()

        strange_chars = set()

        for char in content:
            if ord(char) > 127:
                strange_chars.add(char)

        if strange_chars:
            description = "Non-ascii characters found in report."
            return State(State.Label.ERROR_EXCEPTION, message=description)
        return None

    def strip_changing_values(self, output_file: str):
        """Remove changing values in report to prevent a different event hash being generated each run."""
        # Remove the end of the file. Contains a bunch of changing hashes
        filtered_lines = []

        with open(output_file, "r", encoding="utf-8") as file:
            lines = file.readlines()

        for line in lines:
            if "Hashes" in line:  # Stop at first occurrence of "Hashes"
                break
            filtered_lines.append(line)

        # Write the updated content back to the file
        with open(output_file, "w", encoding="utf-8") as file:
            file.writelines(filtered_lines)

        # List of lines to remove that contain changing filename
        lines_to_remove = [
            "Report For tmp",
            "full path /tmp",
        ]

        with open(output_file, "r", encoding="utf-8") as file:
            lines = file.readlines()

        # Remove lines that match any in the list
        filtered_lines = [line for line in lines if not any(remove_text in line for remove_text in lines_to_remove)]

        # Write the updated content back to the file
        with open(output_file, "w", encoding="utf-8") as file:
            file.writelines(filtered_lines)

    def strip_nulls(self, output_file: str):
        """Strip the null bytes Portex adds to the report."""
        with open(output_file, "rb") as file:
            content = file.read()

        content = content.replace(b"\x00", b"")

        with open(output_file, "wb") as file:
            file.write(content)

    def convert_to_ascii(self, output_file: str):
        """Remove non-ascii chars from file to enable viewing in Azul."""
        with open(output_file, "r") as file:
            content = file.read()

        # this should strip out any strange characters present in the report
        content = unicodedata.normalize("NFKD", content).encode("ascii", "ignore").decode("ascii")

        with open(output_file, "w", encoding="ascii") as file:
            file.write(content)

    def execute(self, job: Job) -> State:
        """Run the plugin."""
        binary = job.get_data().get_filepath()
        temp_dir = tempfile.TemporaryDirectory(prefix=str(Job.id))
        output_path_report = str(os.path.join(temp_dir.name, "PortexReport"))  # nosec
        os.makedirs(os.path.dirname(output_path_report), exist_ok=True)
        output_path_image = str(os.path.join(temp_dir.name, "PortexImage"))
        os.makedirs(os.path.dirname(output_path_image), exist_ok=True)
        try:
            outcome = AzulPluginPortex.run_portex(binary, output_path_report, output_path_image)

            if isinstance(outcome, State):
                return outcome

            self.strip_changing_values(output_path_report)

            # strip nulls before converting to ascii or it would throw an exception
            self.strip_nulls(output_path_report)

            self.convert_to_ascii(output_path_report)

            outcome = self.verify_nonascii_stripped(output_path_report)

            # if non-ascii chars found in report return exception state
            if isinstance(outcome, State):
                return outcome

            with open(output_path_report, "r", encoding="utf-8") as portex_report:
                self.add_text(portex_report.read())

            self.extract_features(output_path_report)

            with open(output_path_image, "rb") as image_file:
                image_bytes = BytesIO(image_file.read())

            try:
                imgSource = Image.open(image_bytes)
            except UnidentifiedImageError:
                # Pillow wasn't able to open this file - magic likely doesn't match
                description = "PIL could not process unsupported image format from Portex."
                return State(State.Label.ERROR_EXCEPTION, message=description)

            byteResult = BytesIO()
            imgSource.save(byteResult, format="WebP")
            image_bytes = byteResult.getvalue()
            self.add_data(DataLabel.SAFE_PNG, {}, image_bytes)

            return State(State.Label.COMPLETED)

        except Exception as e:
            description = f"An error occured running Portex : {str(e)}"
            return State(State.Label.ERROR_EXCEPTION, message=description)


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginPortex)


if __name__ == "__main__":
    main()
