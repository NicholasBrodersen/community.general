# Copyright (c) 2026, Nicholas Brodersen <nicholasbrodersen01@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import hashlib
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


def installed_header():
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


def test_filter_and_normalize_return_only_selected_public_fields():
    header = installed_header()
    header.update(VERIFY={"passed": True, "files": []}, UNKNOWN="private")
    result = rpm.normalize_rpm_info(rpm.filter_rpm_info(header, ["files"]))
    assert result["name"] == "sample"
    assert result["filenames"] == ["/sample"]
    assert result["verify"] == {"passed": True, "files": []}
    assert "version" not in result
    assert "unknown" not in result


def test_file_records_align_metadata_and_reject_missing_fields():
    header = installed_header()
    header["FILENAMES"] = ["/first", "/second"]
    for tag, values in list(header.items()):
        if isinstance(values, list) and tag != "FILENAMES":
            header[tag] = values * 2
    header["LONGFILESIZES"] = [4, 8]
    records = rpm.RPM_SCHEMA.file_records(header)
    assert records["/second"]["size"] == 8
    assert records["/second"]["capabilities"] == ""
    header["FILEMODES"] = [0o100644]
    with pytest.raises(ValueError, match="FILEMODES"):
        rpm.RPM_SCHEMA.file_records(header)


@pytest.mark.parametrize(
    "response, message",
    [
        ((2, "", "database error"), "Failed to list supported RPM tags"),
        ((0, "NAME\nVERSION\n", ""), "Unable to prepare the RPM XML query"),
    ],
)
def test_cli_initialization_reports_rpm_errors(module, response, message):
    module.run_command.return_value = response
    with pytest.raises(AnsibleFailJson) as exc:
        rpm.RPMCLI(module)
    assert exc.value.args[0]["msg"] == message


@pytest.mark.parametrize("selector", ["s*[ab]", "--help"])
def test_query_passes_the_selector_to_rpm_unchanged(cli, module, selector):
    module.run_command.return_value = (0, XML_HEADER, "")
    assert rpm.get_rpm_results(selector, cli)[0]["NAME"] == "sample"
    args = module.run_command.call_args.args[0]
    assert args == ["/usr/bin/rpm", "--query", "--all", "--queryformat", cli.query_format, "name=" + selector]
    assert module.run_command.call_args.kwargs["environ_update"] == {"LC_ALL": "C"}


@pytest.mark.parametrize("response", [(2, "", "database error"), (0, "", "error: regcomp failed\n")])
def test_query_reports_rpm_errors(cli, module, response):
    module.run_command.return_value = response
    with pytest.raises(AnsibleFailJson) as exc:
        rpm.get_rpm_results("[", cli)
    assert exc.value.args[0]["msg"] == "Failed to query installed RPM packages"
    assert exc.value.args[0]["rpm_name"] == "["


@pytest.mark.parametrize("output", ["<rpmHeader>", "<rpmHeader><string>sample</string></rpmHeader>"])
def test_query_reports_unparseable_xml(cli, module, output):
    module.run_command.return_value = (0, output, "")
    with pytest.raises(AnsibleFailJson) as exc:
        rpm.get_rpm_results("sample", cli)
    assert exc.value.args[0]["msg"] == "Failed to parse XML returned by rpm"


def test_verification_parser_accepts_ghost_file_record():
    file = {"path": "/sample"}
    record = rpm._parse_rpm_verify_line(".....UG..  g /sample", {"/sample": file})
    assert record["file"] is file
    assert record["attribute"] == {"code": "g", "name": "ghost"}
    assert [check[0] for check in record["checks"]] == ["user", "group"]


def test_verification_parser_preserves_filenames_and_suffix_messages():
    file = {"path": "/name (suffix) with spaces "}
    record = rpm._parse_rpm_verify_line("S........ /name (suffix) with spaces ", {file["path"]: file})
    assert record["file"] is file
    assert record["message"] is None
    record = rpm._parse_rpm_verify_line(
        "S........ /name (suffix) with spaces  (Permission denied)", {file["path"]: file}
    )
    assert record["file"] is file
    assert record["message"] == "Permission denied"


def test_verification_returns_file_differences(cli, module, mocker):
    module.run_command.return_value = (1, "S........ /sample\n", "")
    mocker.patch.object(rpm.os, "lstat", return_value=SimpleNamespace(st_size=8))
    result = rpm.verify_rpm(cli, installed_header())
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


def test_missing_rpm_file_is_a_difference(cli, module, mocker):
    module.run_command.return_value = (1, "missing   c /sample\n", "")
    mocker.patch.object(rpm.os, "lstat", side_effect=FileNotFoundError())
    result = rpm.verify_rpm(cli, installed_header())
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


@pytest.mark.parametrize(
    "rc, output, message",
    [
        (2, "", "Failed to verify installed RPM package"),
        (1, "malformed\n", "Failed to interpret RPM verification output"),
    ],
)
def test_verification_reports_command_or_parse_failure(cli, module, rc, output, message):
    module.run_command.return_value = (rc, output, "failure")
    with pytest.raises(AnsibleFailJson) as exc:
        rpm.verify_rpm(cli, installed_header())
    assert exc.value.args[0]["msg"] == message


def test_digest_uses_rpm_algorithm_on_real_file(tmp_path):
    content = b"sample contents"
    path = tmp_path / "sample"
    path.write_bytes(content)
    file = {"path": str(path), "digest": "expected-digest"}
    result = rpm.get_digest_failure({"FILEDIGESTALGO": 8}, file)
    assert result == {
        "algorithm": {"id": 8, "name": "sha256"},
        "expected": "expected-digest",
        "actual": hashlib.sha256(content).hexdigest(),
    }


def test_unknown_digest_algorithm_returns_a_structured_error():
    file = {"path": "/sample", "digest": "expected-digest"}
    assert rpm.get_digest_failure({"FILEDIGESTALGO": 999}, file)["error"] == "Unknown RPM file digest algorithm"


def test_symlink_verification_reads_link_itself(tmp_path):
    link = tmp_path / "broken-link"
    link.symlink_to("missing-target")
    assert rpm.get_link_failure({"path": str(link), "link_target": "old-target"}) == {
        "expected": "old-target",
        "actual": "missing-target",
    }


def test_capability_output_preserves_filenames_with_spaces(module):
    module.get_bin_path.return_value = "/usr/sbin/getcap"
    module.run_command.return_value = (0, "/name with spaces cap_net_bind_service=ep\n", "")
    assert rpm.get_actual_capabilities(module, "/name with spaces") == ("cap_net_bind_service=ep", None)


def test_unavailable_getcap_is_a_structured_failure(module):
    module.get_bin_path.return_value = None
    assert rpm.get_capabilities_failure(module, {"path": "/name with spaces", "capabilities": ""}) == {
        "expected": "",
        "actual": None,
        "error": "getcap is not available",
    }
