# Copyright (c) 2026, Nicholas Brodersen <nicholasbrodersen01@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import datetime
import grp
import hashlib
import os
import pwd
import stat
import typing as t
import xml.etree.ElementTree as ET
from enum import Flag, auto
from functools import partial

from ansible.module_utils.basic import AnsibleModule


class RPMFile(t.NamedTuple):
    """Expected RPM metadata for one installed path"""

    path: str
    size: int
    mode: int
    device: int
    mtime: int
    digest: str
    link_target: str
    user: str
    group: str
    capabilities: str


class VerificationFailure(Flag):
    """
    RPM verification outcomes
    *_UNAVAILABLE means the check returned '?'
    """
    NONE = 0
    MISSING = auto()
    SIZE_MISMATCH = auto()
    SIZE_UNAVAILABLE = auto()
    MODE_MISMATCH = auto()
    MODE_UNAVAILABLE = auto()
    DIGEST_MISMATCH = auto()
    DIGEST_UNAVAILABLE = auto()
    DEVICE_MISMATCH = auto()
    DEVICE_UNAVAILABLE = auto()
    LINK_TARGET_MISMATCH = auto()
    LINK_TARGET_UNAVAILABLE = auto()
    USER_MISMATCH = auto()
    USER_UNAVAILABLE = auto()
    GROUP_MISMATCH = auto()
    GROUP_UNAVAILABLE = auto()
    MTIME_MISMATCH = auto()
    MTIME_UNAVAILABLE = auto()
    CAPABILITIES_MISMATCH = auto()
    CAPABILITIES_UNAVAILABLE = auto()


class VerificationRecord:
    """Parse '<result> [<attribute>] <absolute filename> [<messages>]' into named fields"""
    path: str
    result: str
    flags: VerificationFailure
    attribute: t.Optional[dict[str, str]]
    message: t.Optional[str]

    def __init__(self, line: str, known_paths: t.Collection[str]) -> None:
        # Read the status and optional attribute without splitting the filename.
        try:
            result, remaining_text = line.split(maxsplit=1)
            attribute_code = None
            if not remaining_text.startswith("/"):
                attribute_code, remaining_text = remaining_text.split(maxsplit=1)
        except ValueError as exc:
            raise ValueError(f"Unrecognized RPM verification record: {line}") from exc

        if not remaining_text.startswith("/"):
            raise ValueError(f"RPM verification filename must be absolute: {line}")

        flags = RPM_SCHEMA.parse_verification_flags(result)
        attribute = RPM_SCHEMA.file_attribute(attribute_code)

        # Match the entire filename first: '/file (backup)' may be a real filename.
        candidate_path = remaining_text
        messages: list[str] = []
        while candidate_path not in known_paths:
            if not candidate_path.endswith(")") or " (" not in candidate_path:
                raise ValueError(f"RPM verification path is not present in the queried package: {remaining_text}")

            # '/file (error) (replaced)' -> '/file (error)' and 'replaced'.
            without_closing_parenthesis = candidate_path[:-1]
            candidate_path, last_message = without_closing_parenthesis.rsplit(" (", maxsplit=1)
            # Messages are removed from the right; prepend each to keep their original order.
            messages.insert(0, last_message)

        self.path = candidate_path
        self.result = result
        self.flags = flags
        self.attribute = attribute
        self.message = "; ".join(messages) or None


def scalar(values: t.Iterable) -> str | int:
    """Return exactly one decoded value"""
    value, = values
    return value


def _path_component_tags(prefix: str = "") -> dict:
    return {f"{prefix}{suffix}": list for suffix in ("BASENAMES", "DIRNAMES", "DIRINDEXES")}


def _dependency_tags(prefix: str, include_nevrs: bool = True) -> dict:
    suffixes = ("NAME", "VERSION", "FLAGS", "NEVRS") if include_nevrs else ("NAME", "VERSION", "FLAGS")
    return {f"{prefix}{suffix}": list for suffix in suffixes}


def _script_tags(prefix: str) -> dict:
    """Describe a script body, its interpreter, and its flags"""
    return {
        prefix: scalar,
        f"{prefix}PROG": list,
        f"{prefix}FLAGS": scalar,
    }


def _trigger_tags(prefix: str, priorities: bool = False) -> dict:
    """Describe the array tags shared by RPM trigger families"""
    suffixes = [
        "SCRIPTS", "SCRIPTPROG", "SCRIPTFLAGS", "NAME", "VERSION", "FLAGS", "INDEX",
    ]
    if priorities:
        suffixes.append("PRIORITIES")
    suffixes.extend(("CONDS", "TYPE"))

    return {f"{prefix}{suffix}": list for suffix in suffixes}


class RPMSchema:
    """Describe public RPM fields and hide the indexes used to interpret them"""

    def __init__(self, sections: t.Mapping) -> None:
        self._sections = sections

        self._tags = {
            tag: (
                {"parse": definition}
                if callable(definition)
                else definition
            )
            for section in sections.values()
            for tag, definition in section["tags"].items()
        }

        self._required = {
            tag
            for tag, definition in self._tags.items()
            if definition.get("required")
        }

        self._identity_tags = {
            tag
            for tag, definition in self._tags.items()
            if definition.get("identity")
        }

        self._verification_tags = {
            tag
            for tag, definition in self._tags.items()
            if "file_field" in definition or definition.get("verification")
        }

        self._defaults = {
            tag: definition["default"]
            for tag, definition in self._tags.items()
            if "default" in definition
        }

        self._file_tags = {
            tag: definition
            for tag, definition in self._tags.items()
            if "file_field" in definition
        }

        self._file_defaults = {
            definition["file_field"]: definition["file_default"]
            for definition in self._file_tags.values()
            if "file_default" in definition
        }

        self._verify_fields = sorted(
            (
                definition["verify"]
                for definition in self._file_tags.values()
                if "verify" in definition
            ),
            key=lambda verification: verification["position"],
        )

        self.sections = frozenset(sections)

        self.default_sections = frozenset(
            name
            for name, section in sections.items()
            if section.get("default", True)
        )

    def _section_tags(self, categories: t.Iterable[str]) -> set[str]:
        categories = set(categories)
        if "all" in categories:
            categories = self.sections
        return {
            tag
            for category in categories
            for tag in self._sections[category]["tags"]
        }

    def query_format(self, supported_tags: set[str], categories: t.Iterable[str], verify: bool = False) -> str:
        missing = self._required - supported_tags
        if missing:
            raise ValueError(f"RPM does not support required tag(s): {', '.join(sorted(missing))}")

        # Keep package identity available for deduplication and verification
        selected = self._section_tags(categories) | self._identity_tags | self._required
        if verify:
            selected.update(self._verification_tags)

        # Emit our own wrappers and omit tags absent from the header.
        # The space after "[" prevents older RPMs from adding another wrapper.
        # f-string not used here for readability reasons.
        fields = []
        for tag in self._tags:
            if tag not in selected or tag not in supported_tags:
                continue
            value = "%{" + tag + ":xml}"
            field = '<rpmTag name="' + tag + '">[ ' + value + ']</rpmTag>'
            fields.append("%|" + tag + "?{" + field + "}:{}|")
        # Older RPM parsers need literal text between conditional expressions.
        return "<rpmHeader>" + "\n".join(fields) + "</rpmHeader>\n"

    def parse_header(self, element: ET.Element) -> dict:
        if element.tag != "rpmHeader":
            raise ValueError(f"RPM returned an unexpected XML element: {element.tag}")

        header = {}
        for rpm_tag in element:
            name = rpm_tag.get("name", "").upper()

            if rpm_tag.tag != "rpmTag" or not name:
                raise ValueError("RPM returned an invalid or unnamed rpmTag element")
            if name not in self._tags:
                continue
            if name in header:
                raise ValueError(f"RPM returned the tag {name} more than once")
            if len(rpm_tag) == 0:
                raise ValueError(f"RPM returned the tag {name} without a value")

            parse = self._tags[name]["parse"]
            try:
                header[name] = parse(map(_parse_rpm_xml_value, rpm_tag))
            except ValueError as exc:
                raise ValueError(f"Invalid value for RPM tag {name}: {exc}") from exc

        missing = self._required - header.keys()
        if missing:
            raise ValueError(f"RPM header is missing required tag(s): {', '.join(sorted(missing))}")
        return {**self._defaults, **header}

    def select_fields(self, header: t.Mapping, categories: t.Iterable[str]) -> dict:
        selected = self._section_tags(categories) | {"NAME", "VERIFY"}
        return {
            key: value
            for key, value in header.items()
            if key in selected
        }

    def file_records(self, header: t.Mapping) -> dict[str, RPMFile]:
        """Index expected file metadata by path, requiring aligned tag arrays"""
        paths = header.get("FILENAMES", [])
        if not paths:
            return {}

        arrays = {}
        for tag, definition in self._file_tags.items():
            if tag not in header:
                if "file_default" in definition:
                    continue
                raise ValueError(f"RPM header is missing required file tag {tag}")

            values = header[tag]
            if len(values) != len(paths):
                raise ValueError(f"RPM file tag {tag} contains {len(values)} entries, expected {len(paths)}")
            arrays[definition["file_field"]] = values

        records = {}
        for index, path in enumerate(paths):
            metadata = self._file_defaults.copy()
            metadata.update({
                field: values[index]
                for field, values in arrays.items()
            })
            records[path] = RPMFile(path=path, **metadata)
        return records

    def parse_verification_flags(self, result: str) -> VerificationFailure:
        """Combine the outcomes in one RPM result into a single flag value"""
        if result == "missing":
            return VerificationFailure.MISSING
        if len(result) != len(self._verify_fields):
            raise ValueError(f"Invalid RPM verification result: {result}")

        flags = VerificationFailure.NONE
        for character, verification in zip(result, self._verify_fields):
            if character == ".":
                continue
            if character not in verification["flags"]:
                raise ValueError(f"Invalid RPM verification result: {result}")
            flags |= verification["flags"][character]

        return flags

    def unavailable_fields(self, flags: VerificationFailure) -> list[str]:
        """Return the names of fields checks for which RPM could not perform"""
        return [
            definition["file_field"]
            for definition in self._file_tags.values()
            if "verify" in definition and flags & definition["verify"]["flags"]["?"]
        ]

    def file_attribute(self, code: t.Optional[str]) -> t.Optional[dict[str, str]]:
        if code is None:
            return None

        attributes = self._tags["FILEFLAGS"]["attributes"]

        if code not in attributes:
            raise ValueError(f"Unknown RPM file attribute marker: {code}")

        return {"code": code, "name": attributes[code]}

    def digest_algorithm(self, header: t.Mapping) -> tuple[int, t.Optional[str]]:
        definition = self._tags["FILEDIGESTALGO"]
        algorithm_id = header.get("FILEDIGESTALGO")
        if algorithm_id is None:
            algorithm_id = definition["digest_default"]
        algorithm_id = int(algorithm_id)
        return algorithm_id, definition["algorithms"].get(algorithm_id)


# tag definitions are the single source of truth for output categories, types and verification
RPM_SCHEMA = RPMSchema({
    "metadata": {
        "tags": {
            # "identity" tags are queried regardless of the requested output sections.
            "NAME": {"parse": scalar, "required": True, "identity": True},
            "EPOCH": {"parse": scalar, "default": None, "identity": True},
            "EPOCHNUM": scalar,
            "VERSION": {"parse": scalar, "required": True, "identity": True},
            "RELEASE": {"parse": scalar, "required": True, "identity": True},
            "ARCH": {"parse": scalar, "default": None, "identity": True},
            "OS": scalar,
            "NVR": {"parse": scalar, "required": True, "identity": True},
            "NVRA": {"parse": scalar, "identity": True},
            "NEVR": scalar,
            "NEVRA": scalar,
            "EVR": scalar,
            "ARCHSUFFIX": scalar,
            # description
            "SUMMARY": scalar,
            "DESCRIPTION": scalar,
            "LICENSE": scalar,
            "GROUP": scalar,
            "URL": scalar,
            "BUGURL": scalar,
            # distribution info
            "VENDOR": scalar,
            "PACKAGER": scalar,
            "DISTRIBUTION": scalar,
            "DISTTAG": scalar,
            "DISTURL": scalar,
            # build info
            "BUILDTIME": scalar,
            "BUILDHOST": scalar,
            "RPMVERSION": scalar,
            "OPTFLAGS": scalar,
            "PLATFORM": scalar,
            "VCS": scalar,
            "COOKIE": scalar,
            # install info
            "INSTALLTIME": scalar,
            "INSTALLTID": scalar,
            "INSTALLCOLOR": scalar,
            "DBINSTANCE": scalar,
            # source info
            "SOURCERPM": scalar,
            "SOURCENEVR": scalar,
            "SOURCEPACKAGE": scalar,
            "SOURCE": list,
            "PATCH": list,
            "NOSOURCE": list,
            "NOPATCH": list,
            "BUILDARCHS": list,
            "EXCLUDEARCH": list,
            "EXCLUDEOS": list,
            "EXCLUSIVEARCH": list,
            "EXCLUSIVEOS": list,
            "SPEC": scalar,
            # size
            "LONGSIZE": scalar,
            "LONGARCHIVESIZE": scalar,
            "PAYLOADSIZE": scalar,
            "PAYLOADSIZEALT": scalar,
            "PAYLOADFORMAT": scalar,
            "PAYLOADCOMPRESSOR": scalar,
            "PAYLOADFLAGS": scalar,
            # pkg relocation info
            "PREFIXES": list,
            "INSTPREFIXES": list,
            # misc. info
            "ENCODING": scalar,
            "RPMFORMAT": scalar,
            "MODULARITYLABEL": scalar,
            "TRANSLATIONURL": scalar,
            "UPSTREAMRELEASES": scalar,
            "HEADERCOLOR": scalar,
            "SYSUSERS": list,
            # policy info
            "POLICIES": list,
            "POLICYNAMES": list,
            "POLICYTYPES": list,
            "POLICYTYPESINDEXES": list,
            "POLICYFLAGS": list,
        },
    },
    "files": {
        "tags": {
            # paths
            **_path_component_tags(),
            "FILENAMES": {"parse": list, "verification": True},
            "INSTFILENAMES": list,
            # orig. paths for relocated packages
            **_path_component_tags("ORIG"),
            "ORIGFILENAMES": list,
            # file metadata
            "LONGFILESIZES": {
                "parse": list,
                "file_field": "size",
                "verify": {
                    "position": 0,
                    "flags": {
                        "S": VerificationFailure.SIZE_MISMATCH,
                        "?": VerificationFailure.SIZE_UNAVAILABLE,
                    },
                },
            },
            "FILESTATES": list,
            "FILEMODES": {
                "parse": list,
                "file_field": "mode",
                "verify": {
                    "position": 1,
                    "flags": {
                        "M": VerificationFailure.MODE_MISMATCH,
                        "?": VerificationFailure.MODE_UNAVAILABLE,
                    },
                },
            },
            "FILERDEVS": {
                "parse": list,
                "file_field": "device",
                "verify": {
                    "position": 3,
                    "flags": {
                        "D": VerificationFailure.DEVICE_MISMATCH,
                        "?": VerificationFailure.DEVICE_UNAVAILABLE,
                    },
                },
            },
            "FILEDEVICES": list,
            "FILEINODES": list,
            "FILEMTIMES": {
                "parse": list,
                "file_field": "mtime",
                "verify": {
                    "position": 7,
                    "flags": {
                        "T": VerificationFailure.MTIME_MISMATCH,
                        "?": VerificationFailure.MTIME_UNAVAILABLE,
                    },
                },
            },
            "FILEDIGESTS": {
                "parse": list,
                "file_field": "digest",
                "verify": {
                    "position": 2,
                    "flags": {
                        "5": VerificationFailure.DIGEST_MISMATCH,
                        "?": VerificationFailure.DIGEST_UNAVAILABLE,
                    },
                },
            },
            "FILEDIGESTALGO": {
                "parse": scalar,
                "verification": True,
                "digest_default": 0,
                "algorithms": {
                    0: "md5",  # Legacy MD5 when the tag is absent.
                    1: "md5",
                    2: "sha1",
                    3: "ripemd160",
                    5: "md2",
                    6: "tiger192",
                    7: "haval-5-160",
                    8: "sha256",
                    9: "sha384",
                    10: "sha512",
                    11: "sha224",
                    12: "sha3_256",
                    14: "sha3_512",
                },
            },
            "FILELINKTOS": {
                "parse": list,
                "file_field": "link_target",
                "verify": {
                    "position": 4,
                    "flags": {
                        "L": VerificationFailure.LINK_TARGET_MISMATCH,
                        "?": VerificationFailure.LINK_TARGET_UNAVAILABLE,
                    },
                },
            },
            "FILEFLAGS": {
                "parse": list,
                "attributes": {
                    "a": "artifact",
                    "c": "configuration",
                    "d": "documentation",
                    "g": "ghost",
                    "l": "license",
                    "m": "missing_ok",
                    "n": "configuration_noreplace",
                    "r": "readme",
                    "s": "spec",
                },
            },
            "FILEVERIFYFLAGS": list,
            "FILEUSERNAME": {
                "parse": list,
                "file_field": "user",
                "verify": {
                    "position": 5,
                    "flags": {
                        "U": VerificationFailure.USER_MISMATCH,
                        "?": VerificationFailure.USER_UNAVAILABLE,
                    },
                },
            },
            "FILEGROUPNAME": {
                "parse": list,
                "file_field": "group",
                "verify": {
                    "position": 6,
                    "flags": {
                        "G": VerificationFailure.GROUP_MISMATCH,
                        "?": VerificationFailure.GROUP_UNAVAILABLE,
                    },
                },
            },
            "FILELANGS": list,
            "FILECAPS": {
                "parse": list,
                "file_field": "capabilities",
                "file_default": "",
                "verify": {
                    "position": 8,
                    "flags": {
                        "P": VerificationFailure.CAPABILITIES_MISMATCH,
                        "?": VerificationFailure.CAPABILITIES_UNAVAILABLE,
                    },
                },
            },
            "FILECOLORS": list,
            # classification
            "FILECLASS": list,
            "CLASSDICT": list,
            # MIME
            "FILEMIMEINDEX": list,
            "MIMEDICT": list,
            "FILEMIMES": list,
            # hard links
            "FILENLINKS": list,
            # per-file dep. information
            "FILEDEPENDSX": list,
            "FILEDEPENDSN": list,
            "DEPENDSDICT": list,
            "FILEPROVIDE": list,
            "FILEREQUIRE": list,
        },
    },
    "dependencies": {
        "tags": {
            **_dependency_tags("PROVIDE"),
            **_dependency_tags("REQUIRE"),
            **_dependency_tags("CONFLICT"),
            **_dependency_tags("OBSOLETE"),
            **_dependency_tags("RECOMMEND"),
            **_dependency_tags("SUGGEST"),
            **_dependency_tags("SUPPLEMENT"),
            **_dependency_tags("ENHANCE"),
            **_dependency_tags("ORDER", include_nevrs=False),
        },
    },
    "scripts": {
        "tags": {
            **_script_tags("PREIN"),
            **_script_tags("POSTIN"),
            **_script_tags("PREUN"),
            **_script_tags("POSTUN"),
            **_script_tags("PRETRANS"),
            **_script_tags("POSTTRANS"),
            **_script_tags("PREUNTRANS"),
            **_script_tags("POSTUNTRANS"),
            **_script_tags("VERIFYSCRIPT"),
        },
    },
    "triggers": {
        "tags": {
            # pkg triggers
            **_trigger_tags("TRIGGER"),
            **_trigger_tags("FILETRIGGER", priorities=True),
            **_trigger_tags("TRANSFILETRIGGER", priorities=True),
        },
    },
    "signatures": {
        "tags": {
            # pkg signatures
            "OPENPGP": list,
            "SIGPGP": scalar,
            "SIGGPG": scalar,
            "SIGMD5": scalar,
            "DSAHEADER": scalar,
            "RSAHEADER": scalar,
            # header digests
            "SHA1HEADER": scalar,
            "SHA256HEADER": scalar,
            "SHA3_256HEADER": scalar,
            # pkg sizing associated with sigs.
            "LONGSIGSIZE": scalar,
            # pkg payload digests
            "PAYLOADSHA256": list,
            "PAYLOADSHA256ALT": list,
            "PAYLOADSHA512": scalar,
            "PAYLOADSHA512ALT": scalar,
            "PAYLOADSHA3_256": scalar,
            "PAYLOADSHA3_256ALT": scalar,
            # digests for installed pkgs
            "PACKAGEDIGESTS": list,
            "PACKAGEDIGESTALGOS": list,
            # IMA file sigs.
            "FILESIGNATURES": list,
            "FILESIGNATURELENGTH": scalar,
            # fs-verity sigs.
            "VERITYSIGNATURES": list,
            "VERITYSIGNATUREALGO": scalar,
        },
    },
    "changelog": {
        "default": False,
        "tags": {
            "CHANGELOGTIME": list,
            "CHANGELOGNAME": list,
            "CHANGELOGTEXT": list,
        },
    },
})


ALL_SECTIONS = set(RPM_SCHEMA.sections)
DEFAULT_SECTIONS = set(RPM_SCHEMA.default_sections)


class RPMCLI:
    """Run RPM commands and prepare an XML query for the requested sections."""

    def __init__(self, module: AnsibleModule) -> None:
        self.module = module
        self.executable = module.get_bin_path("rpm", required=True)
        rc, stdout, stderr = self.run("--querytags")

        if rc != 0:
            module.fail_json(msg="Failed to list supported RPM tags", rc=rc, stderr=stderr.strip())
        try:
            self.query_format = RPM_SCHEMA.query_format(
                set(stdout.splitlines()), module.params["include"], verify=module.params["verify"],
            )
        except ValueError as exc:
            module.fail_json(msg="Unable to prepare the RPM XML query", error=str(exc))

    def run(self, *arguments: str) -> tuple[int, str, str]:
        return self.module.run_command(
            [self.executable, *arguments], check_rc=False, environ_update={"LC_ALL": "C"},
        )


def _parse_rpm_xml_value(element: ET.Element) -> int | str:
    text = element.text or ""
    if element.tag == "integer":
        return int(text)
    if element.tag == "string":
        return text
    if element.tag == "base64":
        return "".join(text.split())
    raise ValueError(f"RPM returned an unsupported XML value type: {element.tag}")


def _parse_rpm_xml(xml_output: str) -> list[dict]:
    # query emits one <rpmHeader> per package
    # We add a root for the XML document to effectively parse it
    root = ET.fromstring(f"<rpmQueryResults>{xml_output}</rpmQueryResults>")
    return list(map(RPM_SCHEMA.parse_header, root))


def get_rpm_results(rpm_name: str, rpm_cli: RPMCLI) -> list[dict]:
    """Query installed packages using RPM's native name-selector patterns."""
    # RPMs default selector mixes regex and glob syntax
    arguments = [
        "--query", "--all", "--queryformat", rpm_cli.query_format,
        f"name={rpm_name}",
    ]

    rc, stdout, stderr = rpm_cli.run(*arguments)
    # RPM can report selector errors on stderr while returning zero
    if rc != 0 or any(line.startswith("error:") for line in stderr.splitlines()):
        rpm_cli.module.fail_json(
            msg="Failed to query installed RPM packages", rpm_name=rpm_name,
            command=[rpm_cli.executable, *arguments], rc=rc, stderr=stderr.strip(),
        )
    try:
        return _parse_rpm_xml(stdout)
    except (ET.ParseError, ValueError) as exc:
        rpm_cli.module.fail_json(
            msg="Failed to parse XML returned by rpm", rpm_name=rpm_name,
            command=[rpm_cli.executable, *arguments], error=str(exc),
        )


def normalize_rpm_info(rpm_info: dict) -> dict:
    return {key.lower(): value for key, value in rpm_info.items()}


def filter_rpm_info(rpm_header: t.Mapping, categories: t.Iterable[str]) -> dict:
    return RPM_SCHEMA.select_fields(rpm_header, categories)


def format_file_mode(mode: int) -> dict:
    """Describe permissions as octal digits and an ls-style mode string."""
    return {
        "permissions": format(stat.S_IMODE(mode), "04o"),
        "symbolic": stat.filemode(mode),
    }


def format_timestamp(timestamp: int) -> dict:
    return {
        "epoch": int(timestamp),
        "iso": datetime.datetime.fromtimestamp(
            timestamp,
            tz=datetime.timezone.utc,
        ).isoformat(),
    }


def format_device(device: int) -> dict:
    return {
        "raw": device,
        "major": os.major(device),
        "minor": os.minor(device),
    }


def get_username(uid: int) -> str | int:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return uid


def get_groupname(gid: int) -> str | int:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return gid


def calculate_file_digest(path: str, algorithm: str) -> str:
    digest = hashlib.new(algorithm)

    with open(path, "rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def get_link_failure(rpm_file: RPMFile) -> dict:
    failure = {
        "expected": rpm_file.link_target,
        "actual": None,
    }

    try:
        failure["actual"] = os.readlink(rpm_file.path)
    except OSError as exc:
        failure["error"] = str(exc)

    return failure


def get_digest_failure(rpm_header: t.Mapping, rpm_file: RPMFile) -> dict:
    algorithm_id, algorithm = RPM_SCHEMA.digest_algorithm(rpm_header)

    failure = {
        "algorithm": {
            "id": algorithm_id,
            "name": algorithm,
        },
        "expected": rpm_file.digest,
        "actual": None,
    }

    if algorithm is None:
        failure["error"] = "Unknown RPM file digest algorithm"
        return failure

    try:
        failure["actual"] = calculate_file_digest(
            rpm_file.path,
            algorithm,
        )
    except (OSError, ValueError) as exc:
        failure["error"] = str(exc)

    return failure


def get_capabilities_failure(module: AnsibleModule, rpm_file: RPMFile) -> dict:
    failure = {
        "expected": rpm_file.capabilities,
        "actual": None,
    }

    getcap = module.get_bin_path("getcap")
    if getcap is None:
        failure["error"] = "getcap is not available"
        return failure

    rc, stdout, stderr = module.run_command([getcap, "-n", rpm_file.path])
    # getcap can report a per-file error on stderr and still exit successfully
    if rc != 0 or stderr.strip():
        failure["error"] = stderr.strip() or "getcap failed"
        return failure
    if not stdout.strip():
        failure["actual"] = ""
        return failure

    # the filename itself may contain spaces.
    # remove its exact prefix first.
    prefix = f"{rpm_file.path} "
    if stdout.startswith(prefix):
        failure["actual"] = stdout[len(prefix):].strip()
    elif stdout.rstrip("\n") == rpm_file.path:
        failure["actual"] = ""
    else:
        failure["error"] = "Unrecognized getcap output"

    return failure


def get_exists_failure(path: str) -> dict:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return {
            "expected": True,
            "actual": False,
        }
    except OSError as exc:
        return {
            "expected": True,
            "actual": None,
            "error": str(exc),
        }

    return {
        "expected": True,
        "actual": True,
        "error": "RPM reported the file as missing, but it now exists",
    }


def verify_rpm(rpm_cli: RPMCLI, rpm_header: t.Mapping) -> dict:
    # The logic to get the verifiction information is complicated.
    #
    # To increase readability, this function is long
    # for the purpose of reducing indirection,
    # and thus increasing the overall readability and clarity.
    package = rpm_header.get("NVRA", rpm_header["NVR"])
    arguments = [
        "--verify",
        "--nodeps",
        "--noscripts",
        # skip unnessessary header checks.
        # per-file digest verification remains enabled.
        "--nodigest",
        "--nosignature",
        package,
    ]
    rc, stdout, stderr = rpm_cli.run(*arguments)

    diagnostics = {
        "package": package,
        "command": [rpm_cli.executable, *arguments],
        "rc": rc,
        "stdout": stdout,
        "stderr": stderr.strip(),
    }

    try:
        rpm_files = RPM_SCHEMA.file_records(rpm_header)
        nonempty_lines = filter(None, stdout.splitlines())
        parse_record = partial(VerificationRecord, known_paths=rpm_files.keys())
        records = map(parse_record, nonempty_lines)
        # RPM also reports state-only records, such as "(replaced)"
        failed_records = [record for record in records if record.flags]
    except (TypeError, ValueError) as exc:
        rpm_cli.module.fail_json(msg="Failed to interpret RPM verification output", error=str(exc), **diagnostics)

    # nonzero with differences is normal, without differences it is a command failure
    if rc != 0 and not failed_records:
        rpm_cli.module.fail_json(msg="Failed to verify installed RPM package", **diagnostics)

    unavailable_error = "RPM could not perform this verification test"
    failed_files = []
    for record in failed_records:
        flags = record.flags
        failures: dict[str, dict[str, str | int | dict | None]] = {}
        file_result = {
            "path": record.path,
            "result": record.result,
            "failures": failures
        }

        if record.attribute is not None:
            file_result["attribute"] = record.attribute
        if record.message is not None:
            file_result["message"] = record.message
        failed_files.append(file_result)

        if flags & VerificationFailure.MISSING:
            failures["exists"] = get_exists_failure(record.path)
            continue

        try:
            actual = os.lstat(record.path)
        except OSError as exc:
            failures["exists"] = {"expected": True, "actual": None, "error": str(exc)}
            continue

        expected = rpm_files[record.path]
        if flags & (VerificationFailure.SIZE_MISMATCH | VerificationFailure.SIZE_UNAVAILABLE):
            failures["size"] = {"expected": expected.size, "actual": actual.st_size}

        if flags & (VerificationFailure.MODE_MISMATCH | VerificationFailure.MODE_UNAVAILABLE):
            failures["mode"] = {
                "expected": format_file_mode(expected.mode),
                "actual": format_file_mode(actual.st_mode),
            }
            if failures["mode"]["expected"] == failures["mode"]["actual"]:
                failures["mode"]["note"] = "RPM mode verification can also detect non-default ACLs"

        if flags & (VerificationFailure.DIGEST_MISMATCH | VerificationFailure.DIGEST_UNAVAILABLE):
            failures["digest"] = get_digest_failure(rpm_header, expected)

        if flags & (VerificationFailure.DEVICE_MISMATCH | VerificationFailure.DEVICE_UNAVAILABLE):
            failures["device"] = {
                "expected": format_device(expected.device),
                "actual": format_device(actual.st_rdev),
            }

        if flags & (VerificationFailure.LINK_TARGET_MISMATCH | VerificationFailure.LINK_TARGET_UNAVAILABLE):
            failures["link_target"] = get_link_failure(expected)

        if flags & (VerificationFailure.USER_MISMATCH | VerificationFailure.USER_UNAVAILABLE):
            failures["user"] = {
                "expected": expected.user,
                "actual": get_username(actual.st_uid),
                "actual_uid": actual.st_uid,
            }

        if flags & (VerificationFailure.GROUP_MISMATCH | VerificationFailure.GROUP_UNAVAILABLE):
            failures["group"] = {
                "expected": expected.group,
                "actual": get_groupname(actual.st_gid),
                "actual_gid": actual.st_gid,
            }

        if flags & (VerificationFailure.MTIME_MISMATCH | VerificationFailure.MTIME_UNAVAILABLE):
            failures["mtime"] = {
                "expected": format_timestamp(expected.mtime),
                "actual": format_timestamp(int(actual.st_mtime)),
            }

        if flags & (VerificationFailure.CAPABILITIES_MISMATCH | VerificationFailure.CAPABILITIES_UNAVAILABLE):
            failures["capabilities"] = get_capabilities_failure(rpm_cli.module, expected)

        for field in RPM_SCHEMA.unavailable_fields(flags):
            failures[field].setdefault("error", unavailable_error)

    verification = {
        "passed": rc == 0 and not failed_files,
        "files": failed_files
    }

    if stderr.strip():
        verification["messages"] = stderr.splitlines()

    return verification


def populate_rpm_info(rpm_cli: RPMCLI, rpm_header: t.Mapping, verify: bool = False) -> dict:
    """
    copy the queried fields.
    pkg file file verification starts here.
    """
    rpm_info = dict(rpm_header)
    if verify:
        rpm_info["VERIFY"] = verify_rpm(rpm_cli, rpm_header)
    return rpm_info
