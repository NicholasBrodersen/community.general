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
from functools import partial

from ansible.module_utils.basic import AnsibleModule


def scalar(values: t.Iterable) -> str | int:
    """Return exactly one decoded value."""
    value, = values
    return value


def _path_component_tags(prefix: str = "") -> dict:
    return {f"{prefix}{suffix}": list for suffix in ("BASENAMES", "DIRNAMES", "DIRINDEXES")}


def _dependency_tags(prefix: str, include_nevrs: bool = True) -> dict:
    suffixes = ("NAME", "VERSION", "FLAGS", "NEVRS") if include_nevrs else ("NAME", "VERSION", "FLAGS")
    return {f"{prefix}{suffix}": list for suffix in suffixes}


def _script_tags(prefix: str) -> dict:
    """Describe a script body, its interpreter, and its flags."""
    return {
        prefix: scalar,
        f"{prefix}PROG": list,
        f"{prefix}FLAGS": scalar,
    }


def _trigger_tags(prefix: str, priorities: bool = False) -> dict:
    """Describe the array tags shared by RPM trigger families."""
    suffixes = [
        "SCRIPTS", "SCRIPTPROG", "SCRIPTFLAGS", "NAME", "VERSION", "FLAGS", "INDEX",
    ]
    if priorities:
        suffixes.append("PRIORITIES")
    suffixes.extend(("CONDS", "TYPE"))

    return {f"{prefix}{suffix}": list for suffix in suffixes}


class RPMSchema:
    """Describe public RPM fields and hide the indexes used to interpret them."""

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
                definition
                for definition in self._file_tags.values()
                if "verify" in definition
            ),
            key=lambda definition: definition["verify"]["position"],
        )

        self.sections = frozenset(sections)

        self.default_sections = frozenset(
            name
            for name, section in sections.items()
            if section.get("default", True)
        )

    def _section_tags(self, categories: t.Iterable[str]) -> t.Set[str]:
        categories = set(categories)
        if "all" in categories:
            categories = self.sections
        return {
            tag
            for category in categories
            for tag in self._sections[category]["tags"]
        }

    def query_format(self, supported_tags: t.Set[str], categories: t.Iterable[str], verify: bool = False) -> str:
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

    def file_records(self, header: t.Mapping) -> t.Dict[str, dict]:
        """Require complete verification metadata, except fields with schema defaults."""
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

        return {
            path: {
                "path": path,
                **self._file_defaults,
                **{
                    field: values[index]
                    for field, values in arrays.items()
                },
            }
            for index, path in enumerate(paths)
        }

    def parse_verification_checks(self, result: str) -> t.Tuple[t.Tuple[str, bool, t.Callable], ...]:
        """Decode status markers into failed fields, error flags, and collectors."""
        if len(result) != len(self._verify_fields):
            raise ValueError(f"Invalid RPM verification result: {result}")

        checks = []
        for character, definition in zip(result, self._verify_fields):
            verification = definition["verify"]
            if character not in (".", "?", verification["marker"]):
                raise ValueError(f"Invalid RPM verification result: {result}")
            if character != ".":
                checks.append((definition["file_field"], character == "?", verification["collect"]))

        return tuple(checks)

    def file_attribute(self, code: str) -> t.Optional[dict]:
        if code == " ":
            return None

        attributes = self._tags["FILEFLAGS"]["attributes"]

        if code not in attributes:
            raise ValueError(f"Unknown RPM file attribute marker: {code}")

        return {"code": code, "name": attributes[code]}

    def digest_algorithm(self, header: t.Mapping) -> t.Tuple[int, t.Optional[str]]:
        definition = self._tags["FILEDIGESTALGO"]
        algorithm_id = header.get("FILEDIGESTALGO")
        if algorithm_id is None:
            algorithm_id = definition["digest_default"]
        algorithm_id = int(algorithm_id)
        return algorithm_id, definition["algorithms"].get(algorithm_id)


# tag definitions are the single source for output categories, types and verification
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
                    "marker": "S",
                    "collect": lambda module, header, file, file_stat: get_size_failure(file, file_stat),
                },
            },
            "FILESTATES": list,
            "FILEMODES": {
                "parse": list,
                "file_field": "mode",
                "verify": {
                    "position": 1,
                    "marker": "M",
                    "collect": lambda module, header, file, file_stat: get_mode_failure(file, file_stat),
                },
            },
            "FILERDEVS": {
                "parse": list,
                "file_field": "device",
                "verify": {
                    "position": 3,
                    "marker": "D",
                    "collect": lambda module, header, file, file_stat: get_device_failure(file, file_stat),
                },
            },
            "FILEDEVICES": list,
            "FILEINODES": list,
            "FILEMTIMES": {
                "parse": list,
                "file_field": "mtime",
                "verify": {
                    "position": 7,
                    "marker": "T",
                    "collect": lambda module, header, file, file_stat: get_mtime_failure(file, file_stat),
                },
            },
            "FILEDIGESTS": {
                "parse": list,
                "file_field": "digest",
                "verify": {
                    "position": 2,
                    "marker": "5",
                    "collect": lambda module, header, file, file_stat: get_digest_failure(header, file),
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
                    "marker": "L",
                    "collect": lambda module, header, file, file_stat: get_link_failure(file),
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
                    "marker": "U",
                    "collect": lambda module, header, file, file_stat: get_user_failure(file, file_stat),
                },
            },
            "FILEGROUPNAME": {
                "parse": list,
                "file_field": "group",
                "verify": {
                    "position": 6,
                    "marker": "G",
                    "collect": lambda module, header, file, file_stat: get_group_failure(file, file_stat),
                },
            },
            "FILELANGS": list,
            "FILECAPS": {
                "parse": list,
                "file_field": "capabilities",
                "file_default": "",
                "verify": {
                    "position": 8,
                    "marker": "P",
                    "collect": lambda module, header, file, file_stat: get_capabilities_failure(module, file),
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

    def run(self, *arguments: str) -> t.Tuple[int, str, str]:
        return self.module.run_command(
            [self.executable, *arguments], check_rc=False, environ_update={"LC_ALL": "C"},
        )


def _parse_rpm_xml_value(element: ET.Element) -> t.Union[int, str]:
    text = element.text or ""
    if element.tag == "integer":
        try:
            return int(text)
        except ValueError as exc:
            raise ValueError(f"RPM returned an invalid integer value: {text}") from exc
    if element.tag == "string":
        return text
    if element.tag == "base64":
        return "".join(text.split())
    raise ValueError(f"RPM returned an unsupported XML value type: {element.tag}")


def _parse_rpm_xml(xml_output: str) -> t.List[dict]:
    # query emits one <rpmHeader> per package; add a root for the XML document
    root = ET.fromstring(f"<rpmQueryResults>{xml_output}</rpmQueryResults>")
    return list(map(RPM_SCHEMA.parse_header, root))


def get_rpm_results(rpm_name: str, rpm_cli: RPMCLI) -> t.List[dict]:
    """Query installed packages using RPM's native name-selector patterns."""
    # RPMs default selector mixes regex and glob syntax
    arguments = [
        "--query", "--all", "--queryformat", rpm_cli.query_format,
        f"name={rpm_name}",
    ]

    rc, stdout, stderr = rpm_cli.run(*arguments)
    # RPM can report selector errors on stderr while returning zero.
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


def get_username(uid: int) -> t.Union[str, int]:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return uid


def get_groupname(gid: int) -> t.Union[str, int]:
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


def get_size_failure(rpm_file: t.Mapping, file_stat: os.stat_result) -> dict:
    return {
        "expected": rpm_file["size"],
        "actual": file_stat.st_size,
    }


def get_mode_failure(rpm_file: t.Mapping, file_stat: os.stat_result) -> dict:
    failure = {
        "expected": format_file_mode(rpm_file["mode"]),
        "actual": format_file_mode(file_stat.st_mode),
    }

    if failure["expected"] == failure["actual"]:
        failure["note"] = (
            "RPM mode verification can also detect non-default ACLs"
        )

    return failure


def get_user_failure(rpm_file: t.Mapping, file_stat: os.stat_result) -> dict:
    return {
        "expected": rpm_file["user"],
        "actual": get_username(file_stat.st_uid),
        "actual_uid": file_stat.st_uid,
    }


def get_group_failure(rpm_file: t.Mapping, file_stat: os.stat_result) -> dict:
    return {
        "expected": rpm_file["group"],
        "actual": get_groupname(file_stat.st_gid),
        "actual_gid": file_stat.st_gid,
    }


def get_mtime_failure(rpm_file: t.Mapping, file_stat: os.stat_result) -> dict:
    return {
        "expected": format_timestamp(rpm_file["mtime"]),
        "actual": format_timestamp(int(file_stat.st_mtime)),
    }


def get_device_failure(rpm_file: t.Mapping, file_stat: os.stat_result) -> dict:
    return {
        "expected": format_device(rpm_file["device"]),
        "actual": format_device(file_stat.st_rdev),
    }


def get_link_failure(rpm_file: t.Mapping) -> dict:
    path = rpm_file["path"]

    failure = {
        "expected": rpm_file["link_target"],
        "actual": None,
    }

    try:
        failure["actual"] = os.readlink(path)
    except OSError as exc:
        failure["error"] = str(exc)

    return failure


def get_digest_failure(rpm_header: t.Mapping, rpm_file: t.Mapping) -> dict:
    algorithm_id, algorithm = RPM_SCHEMA.digest_algorithm(rpm_header)

    failure = {
        "algorithm": {
            "id": algorithm_id,
            "name": algorithm,
        },
        "expected": rpm_file["digest"],
        "actual": None,
    }

    if algorithm is None:
        failure["error"] = "Unknown RPM file digest algorithm"
        return failure

    try:
        failure["actual"] = calculate_file_digest(
            rpm_file["path"],
            algorithm,
        )
    except (OSError, ValueError) as exc:
        failure["error"] = str(exc)

    return failure


def get_actual_capabilities(module: AnsibleModule, path: str) -> t.Tuple[t.Optional[str], t.Optional[str]]:
    getcap = module.get_bin_path("getcap")
    if getcap is None:
        return None, "getcap is not available"

    rc, stdout, stderr = module.run_command([getcap, "-n", path])
    # getcap can report a per-file error on stderr and still exit successfully
    if rc != 0 or stderr.strip():
        return None, stderr.strip() or "getcap failed"
    if not stdout.strip():
        return "", None

    # the filename itself may contain spaces.
    # remove its exact prefix first.
    prefix = f"{path} "
    if stdout.startswith(prefix):
        return stdout[len(prefix):].strip(), None
    if stdout.rstrip("\n") == path:
        return "", None
    return None, "Unrecognized getcap output"


def get_capabilities_failure(module: AnsibleModule, rpm_file: t.Mapping) -> dict:
    actual, error = get_actual_capabilities(
        module,
        rpm_file["path"],
    )

    failure = {
        "expected": rpm_file["capabilities"],
        "actual": actual,
    }

    if error is not None:
        failure["error"] = error

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


def _parse_rpm_verify_line(line: str, rpm_files: t.Mapping[str, dict]) -> t.Optional[dict]:
    # installed-package paths are absolute.
    # we want to split only the prefix so any kind of spaces or trailing whitespace in the filename are unchanged.
    prefix, separator, path = line.partition(" /")
    fields = prefix.split()
    if not separator or len(fields) not in (1, 2):
        raise ValueError(f"Unrecognized RPM verification record: {line}")

    result = fields[0]
    missing = result == "missing"
    checks = () if missing else RPM_SCHEMA.parse_verification_checks(result)
    attribute = RPM_SCHEMA.file_attribute(fields[1] if len(fields) == 2 else " ")
    rpm_file, message = _resolve_rpm_verify_file("/" + path, rpm_files)
    if not missing and not checks:
        return None  # RPM also reports state-only records, such as "(replaced)"

    return {
        "file": rpm_file,
        "result": result,
        "missing": missing,
        "checks": checks,
        "attribute": attribute,
        "message": message,
    }


def _resolve_rpm_verify_file(reported_path: str, rpm_files: t.Mapping[str, dict]) -> t.Tuple[dict, t.Optional[str]]:
    # match the full filename first, then remove any of RPMs trailing errors and/or
    # state messages until a known path remains.
    #
    # both error and state messages can occur together.
    path = reported_path
    messages = []
    while path not in rpm_files:
        candidate, separator, suffix = path.rpartition(" (")

        if not separator or not suffix.endswith(")"):
            raise ValueError(f"RPM verification path is not present in the queried package: {reported_path}")

        messages.append(suffix[:-1])
        path = candidate

    return rpm_files[path], "; ".join(reversed(messages)) or None


def get_verify_failures(module: AnsibleModule, rpm_header: t.Mapping, record: t.Mapping) -> dict:
    """Collect current values for the failed checks in a parsed record."""
    rpm_file = record["file"]
    if record["missing"]:
        return {
            "exists": get_exists_failure(rpm_file["path"])
        }

    try:
        file_stat = os.lstat(rpm_file["path"])
    except OSError as exc:
        return {
            "exists": {
                "expected": True,
                "actual": None,
                "error": str(exc),
            }
        }

    failures = {}
    for field, unknown, collect in record["checks"]:
        failure = collect(module, rpm_header, rpm_file, file_stat)
        if unknown:
            failure.setdefault("error", "RPM could not perform this verification test")
        failures[field] = failure
    return failures


def collect_verification(module: AnsibleModule, rpm_header: t.Mapping, record: t.Mapping) -> dict:
    """Build the public verification result from a parsed record."""
    result = {
        "path": record["file"]["path"],
        "result": record["result"],
        "failures": get_verify_failures(module, rpm_header, record),
    }
    if record["attribute"] is not None:
        result["attribute"] = record["attribute"]
    if record["message"] is not None:
        result["message"] = record["message"]
    return result


def verify_rpm(rpm_cli: RPMCLI, rpm_header: t.Mapping) -> dict:
    """Verify installed files, excluding dependencies, scripts, and header checks."""
    package = rpm_header.get("NVRA", rpm_header["NVR"])
    arguments = [
        "--verify", "--nodeps", "--noscripts",
        # skip unnessessary header checks.
        # per-file digest verification remains enabled.
        "--nodigest", "--nosignature", package,
    ]
    rc, stdout, stderr = rpm_cli.run(*arguments)
    diagnostics = {
        "package": package, "command": [rpm_cli.executable, *arguments],
        "rc": rc, "stdout": stdout, "stderr": stderr.strip(),
    }
    try:
        rpm_files = RPM_SCHEMA.file_records(rpm_header)
        parse_record = partial(_parse_rpm_verify_line, rpm_files=rpm_files)
        records = map(parse_record, filter(None, stdout.splitlines()))
        parsed_records = list(filter(None, records))
    except (TypeError, ValueError) as exc:
        rpm_cli.module.fail_json(msg="Failed to interpret RPM verification output", error=str(exc), **diagnostics)

    # nonzero with differences is normal, without differences it is a command failure
    if rc != 0 and not parsed_records:
        rpm_cli.module.fail_json(msg="Failed to verify installed RPM package", **diagnostics)

    collect_record = partial(collect_verification, rpm_cli.module, rpm_header)
    failed_files = list(map(collect_record, parsed_records))
    passed_result = rc == 0 and not failed_files
    verification = {
        "passed": passed_result,
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
