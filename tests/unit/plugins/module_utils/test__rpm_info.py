# Copyright (c) 2026, Nicholas Brodersen <nicholasbrodersen01@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import hashlib
import os
from types import SimpleNamespace

import pytest
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import (
    AnsibleFailJson,
    fail_json,
)

from ansible_collections.community.general.plugins.module_utils import _rpm_info as rpm

XML_HEADER = (
    '<rpmHeader><rpmTag name="NAME"><string>sample</string></rpmTag>'
    '<rpmTag name="VERSION"><string>1.0</string></rpmTag>'
    '<rpmTag name="RELEASE"><string>1</string></rpmTag>'
    '<rpmTag name="NVR"><string>sample-1.0-1</string></rpmTag></rpmHeader>'
)


@pytest.fixture
def rpm_header():
    return {
        "NAME": "sample",
        "VERSION": "1.0",
        "RELEASE": "1",
        "NVR": "sample-1.0-1",
        "NVRA": "sample-1.0-1.noarch",
        "FILENAMES": ["/sample"],
        "LONGFILESIZES": [4],
        "FILEMODES": [0o100644],
        "FILERDEVS": [0],
        "FILEMTIMES": [0],
        "FILEDIGESTS": ["expected-digest"],
        "FILELINKTOS": [""],
        "FILEUSERNAME": ["root"],
        "FILEGROUPNAME": ["root"],
    }


@pytest.fixture
def module(mocker):
    ansible_module = mocker.Mock(spec=AnsibleModule)
    ansible_module.params = {"include": ["metadata"], "verify": False}
    ansible_module.get_bin_path.return_value = "/usr/bin/rpm"
    ansible_module.run_command.return_value = (0, "NAME\nVERSION\nRELEASE\nNVR\nARCH\nFILENAMES\n", "")
    ansible_module.fail_json.side_effect = fail_json
    return ansible_module


@pytest.fixture
def cli(module):
    return rpm.RPMCLI(module)


@pytest.fixture
def rpm_file(rpm_header):
    return rpm.RPM_SCHEMA.file_records(rpm_header)["/sample"]


def test_query_format_selects_fields_and_emits_named_xml_tags():
    supported = {"NAME", "VERSION", "RELEASE", "NVR", "SUMMARY", "FILENAMES"}
    query = rpm.RPM_SCHEMA.query_format(supported, ["metadata"])
    assert '%|NAME?{<rpmTag name="NAME">[ %{NAME:xml}]</rpmTag>}:{}|' in query
    assert '%|SUMMARY?{<rpmTag name="SUMMARY">[ %{SUMMARY:xml}]</rpmTag>}:{}|' in query
    assert "\n%|VERSION?{" in query
    assert "FILENAMES" not in query
    assert "FILENAMES" in rpm.RPM_SCHEMA.query_format(supported, ["metadata"], verify=True)


def test_query_format_requires_package_identity():
    with pytest.raises(ValueError, match="NVR"):
        rpm.RPM_SCHEMA.query_format({"NAME", "VERSION", "RELEASE"}, [])


def test_xml_parser_decodes_arrays_and_defaults():
    xml = XML_HEADER.replace(
        "</rpmHeader>",
        '<rpmTag name="PATCH"><string>change.patch</string></rpmTag>'
        '<rpmTag name="REQUIREFLAGS"><integer>8</integer><integer>12</integer></rpmTag>'
        '<rpmTag name="FUTURETAG"><future>ignored</future></rpmTag></rpmHeader>',
    )
    headers = rpm._parse_rpm_xml(xml + xml)
    assert (
        headers
        == [
            {
                "NAME": "sample",
                "VERSION": "1.0",
                "RELEASE": "1",
                "NVR": "sample-1.0-1",
                "EPOCH": None,
                "ARCH": None,
                "PATCH": ["change.patch"],
                "REQUIREFLAGS": [8, 12],
            }
        ]
        * 2
    )


@pytest.mark.parametrize(
    "extra",
    [
        '<rpmTag name="NAME"><string>again</string></rpmTag>',
        '<rpmTag name="SUMMARY"><string>one</string><string>two</string></rpmTag>',
        '<rpmTag name="SUMMARY"><integer>invalid</integer></rpmTag>',
    ],
)
def test_xml_parser_rejects_ambiguous_or_invalid_fields(extra):
    with pytest.raises(ValueError):
        rpm._parse_rpm_xml(XML_HEADER.replace("</rpmHeader>", extra + "</rpmHeader>"))


def test_filter_and_normalize_return_only_selected_public_fields(rpm_header):
    rpm_header.update(VERIFY={"passed": True, "files": []}, UNKNOWN="private")
    result = rpm.normalize_rpm_info(rpm.filter_rpm_info(rpm_header, ["files"]))
    assert result["name"] == "sample"
    assert result["filenames"] == ["/sample"]
    assert result["verify"] == {"passed": True, "files": []}
    assert "version" not in result
    assert "unknown" not in result


def test_file_records_align_metadata_and_reject_missing_fields(rpm_header):
    rpm_header["FILENAMES"] = ["/first", "/second"]
    for tag, values in list(rpm_header.items()):
        if isinstance(values, list) and tag != "FILENAMES":
            rpm_header[tag] = values * 2
    rpm_header["LONGFILESIZES"] = [4, 8]
    records = rpm.RPM_SCHEMA.file_records(rpm_header)
    assert records["/second"].size == 8
    assert records["/second"].capabilities == ""
    rpm_header["FILEMODES"] = [0o100644]
    with pytest.raises(ValueError, match="FILEMODES"):
        rpm.RPM_SCHEMA.file_records(rpm_header)


@pytest.mark.parametrize("response", [(2, "", "database error"), (0, "NAME\nVERSION\n", "")])
def test_cli_initialization_reports_rpm_errors(module, response):
    module.run_command.return_value = response
    with pytest.raises(AnsibleFailJson) as exc:
        rpm.RPMCLI(module)
    failure = exc.value.args[0]
    if response[0]:
        assert failure["rc"] == response[0]
        assert failure["stderr"] == response[2]
    else:
        assert "NVR" in failure["error"]


@pytest.mark.parametrize("selector", ["s*[ab]", "--help"])
def test_query_passes_the_selector_to_rpm_unchanged(cli, module, selector):
    module.run_command.return_value = (0, XML_HEADER, "")
    assert rpm.get_rpm_results(selector, cli)[0]["NAME"] == "sample"
    args = module.run_command.call_args.args[0]
    assert args == ["/usr/bin/rpm", "--query", "--all", "--queryformat", cli.query_format, "name=" + selector]
    assert module.run_command.call_args.kwargs["environ_update"] == {"LC_ALL": "C"}


@pytest.mark.parametrize(
    "response, parse_error",
    [
        ((2, "", "database error"), False),
        ((0, "", "error: regcomp failed\n"), False),
        ((0, "<rpmHeader>", ""), True),
        ((0, "<rpmHeader><string>sample</string></rpmHeader>", ""), True),
    ],
)
def test_query_reports_command_or_parse_failure(cli, module, response, parse_error):
    module.run_command.return_value = response
    with pytest.raises(AnsibleFailJson) as exc:
        rpm.get_rpm_results("sample", cli)
    failure = exc.value.args[0]
    assert failure["rpm_name"] == "sample"
    assert bool(failure.get("error")) == parse_error
    if not parse_error:
        assert failure["rc"] == response[0]
        assert failure["stderr"] == response[2].strip()


@pytest.mark.parametrize(
    "result, mismatch, unavailable",
    [
        ("S........", rpm.VerificationFailure.SIZE_MISMATCH, rpm.VerificationFailure.SIZE_UNAVAILABLE),
        (".M.......", rpm.VerificationFailure.MODE_MISMATCH, rpm.VerificationFailure.MODE_UNAVAILABLE),
        ("..5......", rpm.VerificationFailure.DIGEST_MISMATCH, rpm.VerificationFailure.DIGEST_UNAVAILABLE),
        ("...D.....", rpm.VerificationFailure.DEVICE_MISMATCH, rpm.VerificationFailure.DEVICE_UNAVAILABLE),
        ("....L....", rpm.VerificationFailure.LINK_TARGET_MISMATCH, rpm.VerificationFailure.LINK_TARGET_UNAVAILABLE),
        (".....U...", rpm.VerificationFailure.USER_MISMATCH, rpm.VerificationFailure.USER_UNAVAILABLE),
        ("......G..", rpm.VerificationFailure.GROUP_MISMATCH, rpm.VerificationFailure.GROUP_UNAVAILABLE),
        (".......T.", rpm.VerificationFailure.MTIME_MISMATCH, rpm.VerificationFailure.MTIME_UNAVAILABLE),
        ("........P", rpm.VerificationFailure.CAPABILITIES_MISMATCH, rpm.VerificationFailure.CAPABILITIES_UNAVAILABLE),
    ],
)
def test_verification_flags_distinguish_each_mismatch_from_an_unavailable_check(result, mismatch, unavailable):
    assert rpm.RPM_SCHEMA.parse_verification_flags(result) == mismatch
    unchecked = "".join("." if character == "." else "?" for character in result)
    assert rpm.RPM_SCHEMA.parse_verification_flags(unchecked) == unavailable


@pytest.mark.parametrize(
    "result, expected",
    [
        (".........", rpm.VerificationFailure.NONE),
        ("missing", rpm.VerificationFailure.MISSING),
        ("S.?......", rpm.VerificationFailure.SIZE_MISMATCH | rpm.VerificationFailure.DIGEST_UNAVAILABLE),
    ],
)
def test_verification_flags_combine_only_the_reported_outcomes(result, expected):
    assert rpm.RPM_SCHEMA.parse_verification_flags(result) == expected


@pytest.mark.parametrize("result", ["S.......", "M........"])
def test_verification_flags_reject_invalid_length_or_marker_position(result):
    with pytest.raises(ValueError):
        rpm.RPM_SCHEMA.parse_verification_flags(result)


@pytest.mark.parametrize(
    "path, suffix, message",
    [
        ("/name (suffix) with spaces ", "", None),
        ("/name (suffix) with spaces ", " (Permission denied)", "Permission denied"),
        ("/name (suffix)", " (Permission denied) (replaced)", "Permission denied; replaced"),
        ("/name (Permission denied)", "", None),
        ("/name\twith  spaces ", " (Permission denied)", "Permission denied"),
    ],
)
def test_verification_parser_preserves_filenames_and_suffix_messages(path, suffix, message):
    # Both names are installed; an exact match must win over removing parentheses.
    record = rpm.VerificationRecord(f"S........ {path}{suffix}", known_paths={"/name", path})
    assert record.path == path
    assert record.message == message


@pytest.mark.parametrize("line", ["S........ c", "S........ c relative-path", "S........ c /unknown"])
def test_verification_parser_rejects_missing_relative_or_unknown_filenames(line):
    with pytest.raises(ValueError):
        rpm.VerificationRecord(line, known_paths={"/sample"})


def test_verification_returns_file_differences(cli, module, mocker, rpm_header):
    module.run_command.return_value = (1, "S........ /sample\n", "")
    mocker.patch.object(rpm.os, "lstat", return_value=SimpleNamespace(st_size=8))
    result = rpm.verify_rpm(cli, rpm_header)
    assert result == {
        "passed": False,
        "files": [{"path": "/sample", "result": "S........", "failures": {"size": {"expected": 4, "actual": 8}}}],
    }
    assert module.run_command.call_args.args[0] == [
        "/usr/bin/rpm",
        "--verify",
        "--nodeps",
        "--noscripts",
        "--nodigest",
        "--nosignature",
        "sample-1.0-1.noarch",
    ]


@pytest.mark.parametrize("status", ["SM5DLUGTP", "?????????", "S?5?L?G?P"])
def test_verification_collects_each_reported_field(cli, module, mocker, rpm_header, status):
    rpm_header["FILEDIGESTALGO"] = 8
    module.run_command.side_effect = [
        (1, f"{status}  g /sample (Permission denied)\n", "warning: sample\n"),
        (0, "/sample cap_net_bind_service=ep\n", ""),
    ]
    module.get_bin_path.return_value = "/usr/sbin/getcap"
    mocker.patch.object(
        rpm.os,
        "lstat",
        return_value=SimpleNamespace(
            st_size=8,
            st_mode=0o100600,
            st_rdev=os.makedev(1, 2),
            st_uid=123,
            st_gid=456,
            st_mtime=1.75,
        ),
    )
    mocker.patch.object(rpm.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="owner"))
    mocker.patch.object(rpm.grp, "getgrgid", return_value=SimpleNamespace(gr_name="group"))
    mocker.patch.object(rpm.os, "readlink", return_value="new-target")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"contents"))

    result = rpm.verify_rpm(cli, rpm_header)
    assert result["passed"] is False
    assert result["messages"] == ["warning: sample"]
    assert len(result["files"]) == 1
    file_result = result["files"][0]
    assert file_result["path"] == "/sample"
    assert file_result["result"] == status
    assert file_result["attribute"] == {"code": "g", "name": "ghost"}
    assert file_result["message"] == "Permission denied"
    expected_failures = {
        "size": {"expected": 4, "actual": 8},
        "mode": {
            "expected": {"permissions": "0644", "symbolic": "-rw-r--r--"},
            "actual": {"permissions": "0600", "symbolic": "-rw-------"},
        },
        "digest": {
            "algorithm": {"id": 8, "name": "sha256"},
            "expected": "expected-digest",
            "actual": hashlib.sha256(b"contents").hexdigest(),
        },
        "device": {
            "expected": {"raw": 0, "major": 0, "minor": 0},
            "actual": {"raw": os.makedev(1, 2), "major": 1, "minor": 2},
        },
        "link_target": {"expected": "", "actual": "new-target"},
        "user": {"expected": "root", "actual": "owner", "actual_uid": 123},
        "group": {"expected": "root", "actual": "group", "actual_gid": 456},
        "mtime": {
            "expected": {"epoch": 0, "iso": "1970-01-01T00:00:00+00:00"},
            "actual": {"epoch": 1, "iso": "1970-01-01T00:00:01+00:00"},
        },
        "capabilities": {"expected": "", "actual": "cap_net_bind_service=ep"},
    }
    failures = file_result["failures"]
    assert failures.keys() == expected_failures.keys()
    for marker, field in zip(status, expected_failures):
        failure = failures[field].copy()
        if marker == "?":
            assert failure.pop("error")
        assert failure == expected_failures[field]


@pytest.mark.parametrize("output", ["", "\n......... /sample (replaced)\n"])
def test_successful_verification_ignores_state_only_records(cli, module, mocker, rpm_header, output):
    module.run_command.return_value = (0, output, "")
    lstat = mocker.patch.object(rpm.os, "lstat")
    assert rpm.verify_rpm(cli, rpm_header) == {"passed": True, "files": []}
    lstat.assert_not_called()


@pytest.mark.parametrize(
    "rc, output, parse_error",
    [
        (2, "", False),
        (2, "......... /sample (replaced)\n", False),
        (1, "malformed\n", True),
        (1, "S........ /sample\ninvalid record\n", True),
    ],
)
def test_verification_reports_command_or_parse_failure(cli, module, mocker, rpm_header, rc, output, parse_error):
    module.run_command.return_value = (rc, output, "database error")
    lstat = mocker.patch.object(rpm.os, "lstat")
    with pytest.raises(AnsibleFailJson) as exc:
        rpm.verify_rpm(cli, rpm_header)
    failure = exc.value.args[0]
    assert failure["rc"] == rc
    assert failure["stdout"] == output
    assert failure["stderr"] == "database error"
    assert bool(failure.get("error")) == parse_error
    lstat.assert_not_called()


def test_failed_stat_preserves_the_reported_difference(cli, module, mocker, rpm_header):
    module.run_command.return_value = (1, "S........ /sample\n", "")
    mocker.patch.object(rpm.os, "lstat", side_effect=PermissionError("not permitted"))
    result = rpm.verify_rpm(cli, rpm_header)
    assert result == {
        "passed": False,
        "files": [
            {
                "path": "/sample",
                "result": "S........",
                "failures": {"exists": {"expected": True, "actual": None, "error": "not permitted"}},
            }
        ],
    }


def test_unreadable_marker_preserves_a_more_specific_error(cli, module, mocker, rpm_header):
    rpm_header["FILEDIGESTALGO"] = 999
    module.run_command.return_value = (1, "..?...... /sample\n", "")
    mocker.patch.object(rpm.os, "lstat")
    result = rpm.verify_rpm(cli, rpm_header)
    assert result["files"][0]["failures"]["digest"]["error"] == "Unknown RPM file digest algorithm"


def test_equal_mode_values_retain_the_acl_explanation(cli, module, mocker, rpm_header):
    module.run_command.return_value = (1, ".M....... /sample\n", "")
    mocker.patch.object(rpm.os, "lstat", return_value=SimpleNamespace(st_mode=0o100644))
    result = rpm.verify_rpm(cli, rpm_header)
    failure = result["files"][0]["failures"]["mode"]
    assert failure["expected"] == failure["actual"]
    assert "ACL" in failure["note"]


def test_missing_rpm_file_is_a_difference(cli, module, mocker, rpm_header):
    module.run_command.return_value = (1, "missing   c /sample\n", "")
    mocker.patch.object(rpm.os, "lstat", side_effect=FileNotFoundError())
    result = rpm.verify_rpm(cli, rpm_header)
    assert result == {
        "passed": False,
        "files": [
            {
                "path": "/sample",
                "result": "missing",
                "attribute": {"code": "c", "name": "configuration"},
                "failures": {"exists": {"expected": True, "actual": False}},
            }
        ],
    }


def test_digest_uses_rpm_algorithm_on_real_file(tmp_path, rpm_file):
    content = b"sample contents"
    path = tmp_path / "sample"
    path.write_bytes(content)
    rpm_file = rpm_file._replace(path=str(path))
    result = rpm.get_digest_failure({"FILEDIGESTALGO": 8}, rpm_file)
    assert result == {
        "algorithm": {"id": 8, "name": "sha256"},
        "expected": "expected-digest",
        "actual": hashlib.sha256(content).hexdigest(),
    }


def test_symlink_verification_reads_link_itself(tmp_path, rpm_file):
    link = tmp_path / "broken-link"
    link.symlink_to("missing-target")
    rpm_file = rpm_file._replace(path=str(link), link_target="old-target")
    assert rpm.get_link_failure(rpm_file) == {
        "expected": "old-target",
        "actual": "missing-target",
    }


@pytest.mark.parametrize(
    "output, actual",
    [
        ("/name with spaces cap_net_bind_service=ep\n", "cap_net_bind_service=ep"),
        ("", ""),
        ("/name with spaces\n", ""),
    ],
)
def test_capability_output_preserves_filenames_with_spaces(module, rpm_file, output, actual):
    rpm_file = rpm_file._replace(path="/name with spaces", capabilities="cap_chown=ep")
    module.get_bin_path.return_value = "/usr/sbin/getcap"
    module.run_command.return_value = (0, output, "")
    assert rpm.get_capabilities_failure(module, rpm_file) == {
        "expected": "cap_chown=ep",
        "actual": actual,
    }


@pytest.mark.parametrize(
    "response",
    [
        (1, "", ""),
        (0, "/sample cap_net_bind_service=ep\n", "permission denied\n"),
        (0, "unexpected output\n", ""),
    ],
)
def test_capability_collection_reports_command_and_parse_errors(module, rpm_file, response):
    module.get_bin_path.return_value = "/usr/sbin/getcap"
    module.run_command.return_value = response
    result = rpm.get_capabilities_failure(module, rpm_file)
    assert result["expected"] == rpm_file.capabilities
    assert result["actual"] is None
    assert result["error"]
    if response[2]:
        assert result["error"] == response[2].strip()


def test_unavailable_getcap_is_a_structured_failure(module, rpm_file):
    module.get_bin_path.return_value = None
    failure = rpm.get_capabilities_failure(module, rpm_file)
    assert failure.pop("error")
    assert failure == {"expected": "", "actual": None}
