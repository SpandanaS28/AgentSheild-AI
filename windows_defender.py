import os
import subprocess
import tempfile
from pathlib import Path


# =========================================
# FIND MICROSOFT DEFENDER
# =========================================

def find_defender_executable():

    program_data = os.environ.get(
        "ProgramData"
    )

    if not program_data:
        return None

    platform_directory = (
        Path(program_data)
        / "Microsoft"
        / "Windows Defender"
        / "Platform"
    )

    if not platform_directory.exists():
        return None

    candidates = list(
        platform_directory.glob(
            "*/MpCmdRun.exe"
        )
    )

    if not candidates:
        return None

    candidates.sort(
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    return candidates[0]


# =========================================
# WINDOWS DEFENDER SCAN
# =========================================

def scan_with_windows_defender(
    filename: str,
    content: bytes,
):

    defender_path = (
        find_defender_executable()
    )

    if defender_path is None:

        return {
            "available": False,
            "checked": False,
            "engine": "Microsoft Defender Antivirus",
            "status": "unavailable",
            "threat_detected": False,
            "message": (
                "Microsoft Defender Antivirus "
                "could not be located."
            ),
        }


    safe_name = (
        os.path.basename(filename)
        or "uploaded-file"
    )

    suffix = Path(
        safe_name
    ).suffix


    temporary_path = None

    try:

        # =================================
        # SAVE UPLOAD TO TEMPORARY FILE
        #
        # Defender needs a real filesystem
        # path to scan.
        # =================================

        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=suffix,
            delete=False,
        ) as temporary_file:

            temporary_file.write(
                content
            )

            temporary_path = (
                temporary_file.name
            )


        # =================================
        # RUN DEFENDER CUSTOM SCAN
        #
        # -ScanType 3 = custom file scan
        #
        # -DisableRemediation prevents
        # AgentShield from intentionally
        # asking Defender to remediate the
        # temporary scan target.
        # =================================

        process = subprocess.run(
            [
                str(defender_path),
                "-Scan",
                "-ScanType",
                "3",
                "-File",
                temporary_path,
                "-DisableRemediation",
            ],
            capture_output=True,
            text=True,
            timeout=90,
            errors="replace",
        )


        output = (
            (
                process.stdout
                or ""
            )
            +
            "\n"
            +
            (
                process.stderr
                or ""
            )
        ).strip()


        normalized_output = (
            output.lower()
        )


        # =================================
        # CLEAN RESULT
        # =================================

        if (
            "found no threats"
            in normalized_output
        ):

            return {
                "available": True,
                "checked": True,
                "engine": (
                    "Microsoft Defender Antivirus"
                ),
                "status": "clean",
                "threat_detected": False,
                "message": (
                    "Microsoft Defender completed "
                    "the scan and found no threats."
                ),
            }


        # =================================
        # POSSIBLE DETECTION
        #
        # We intentionally avoid claiming
        # malware unless Defender output
        # indicates a threat was found.
        # =================================

        if (
            "threat"
            in normalized_output
            and
            "found no threats"
            not in normalized_output
            and
            process.returncode != 0
        ):

            return {
                "available": True,
                "checked": True,
                "engine": (
                    "Microsoft Defender Antivirus"
                ),
                "status": "detected",
                "threat_detected": True,
                "message": (
                    "Microsoft Defender reported "
                    "a possible threat."
                ),
            }


        # =================================
        # SCAN ERROR / UNKNOWN RESULT
        # =================================

        return {
            "available": True,
            "checked": False,
            "engine": (
                "Microsoft Defender Antivirus"
            ),
            "status": "unknown",
            "threat_detected": False,
            "message": (
                "Microsoft Defender was available, "
                "but AgentShield could not confirm "
                "a clean or detected result."
            ),
            "return_code": (
                process.returncode
            ),
        }


    except subprocess.TimeoutExpired:

        return {
            "available": True,
            "checked": False,
            "engine": (
                "Microsoft Defender Antivirus"
            ),
            "status": "timeout",
            "threat_detected": False,
            "message": (
                "Microsoft Defender scan "
                "timed out."
            ),
        }


    except Exception as exc:

        return {
            "available": True,
            "checked": False,
            "engine": (
                "Microsoft Defender Antivirus"
            ),
            "status": "error",
            "threat_detected": False,
            "message": (
                "Microsoft Defender scan "
                "could not be completed."
            ),
            "error": str(exc),
        }


    finally:

        # =================================
        # DELETE TEMPORARY FILE
        # =================================

        if temporary_path:

            try:

                os.remove(
                    temporary_path
                )

            except OSError:

                pass