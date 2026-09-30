# Copyright (c) 2026, Nicholas Brodersen <nicholasbrodersen01@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args

from ansible_collections.community.general.plugins.modules import rpm_info


def package(name="sample", version="1.0", release="1", epoch=None, arch="noarch"):
    return {
        "NAME": name,
        "VERSION": version,
        "RELEASE": release,
        "EPOCH": epoch,
        "ARCH": arch,
        "NVR": f"{name}-{version}-{release}",
        "NVRA": f"{name}-{version}-{release}.{arch}",
        "PROVIDENAME": [f"{name}-{version}-{release}-{epoch}-{arch}"],
        "CHANGELOGTEXT": ["A test release"],
    }


def query_xml(headers, query_format):
    """Simulate RPM's wire format, including omission of unrequested and absent tags."""
    output = []
    for header in headers:
        element = ET.Element("rpmHeader")
        for name, value in header.items():
            if value is None or "%{" + name + ":xml}" not in query_format:
                continue
            tag = ET.SubElement(element, "rpmTag", name=name)
            for item in value if isinstance(value, list) else [value]:
                ET.SubElement(tag, "integer" if isinstance(item, int) else "string").text = str(item)
        output.append(ET.tostring(element, encoding="unicode"))
    return "".join(output)


@pytest.fixture
def run_module(mocker, capfd):
    def run(params, matches):
        def command(args, **kwargs):
            if args[1] == "--querytags":
                return 0, "\n".join(package()), ""
            if args[1] == "--query":
                return 0, query_xml(matches[args[-1]], args[4]), ""
            if args[1] == "--verify":
                return 0, "", ""
            raise AssertionError(f"Unexpected command: {args}")

        mocker.patch.object(AnsibleModule, "get_bin_path", return_value="/usr/bin/rpm")
        commands = mocker.patch.object(AnsibleModule, "run_command", side_effect=command)
        with set_module_args(dict(params)), pytest.raises(SystemExit) as exc:
            rpm_info.main()
        stdout = capfd.readouterr()[0]
        result = json.loads(stdout)
        assert exc.value.code == 0, result
        assert not result["changed"]
        assert not result.get("failed", False)
        return result["packages"], commands

    return run


@pytest.mark.parametrize(
    "include",
    [[], ["files"], ["changelog"], ["metadata"], ["all"]],
)
def test_selected_sections_return_the_requested_fields(run_module, include):
    result = run_module({"name": ["sample"], "include": include}, {"name=sample": [package()]})[0]
    assert len(result) == 1
    assert result[0]["name"] == "sample"
    assert ("version" in result[0]) is bool(set(include) & {"metadata", "all"})
    assert ("changelogtext" in result[0]) is bool(set(include) & {"changelog", "all"})


def test_sorting_and_deduplication_use_full_identity_before_filtering(run_module):
    ordered = [
        package("alpha"),
        package(arch=None),
        package(),
        package(arch="x86_64"),
        package(release="2"),
        package(version="2.0"),
        package(epoch=1),
    ]
    matches = {"name=s*": list(reversed(ordered)), "name=sample": ordered[1:]}
    result = run_module({"name": ["s*", "sample"], "include": ["dependencies"]}, matches)[0]
    assert result == [{"name": p["NAME"], "providename": p["PROVIDENAME"]} for p in ordered]


def test_default_selection_excludes_changelog_and_verification(run_module):
    result, commands = run_module({"name": ["sample"]}, {"name=sample": [package()]})
    assert result[0]["version"] == "1.0"
    assert "changelogtext" not in result[0]
    assert "verify" not in result[0]
    assert all(call.args[0][1] != "--verify" for call in commands.call_args_list)


def test_verification_runs_once_for_overlapping_selectors(run_module):
    result, commands = run_module(
        {"name": ["*", "sample"], "include": [], "verify": True, "_ansible_check_mode": True},
        {"name=*": [package()], "name=sample": [package()]},
    )
    assert result == [{"name": "sample", "verify": {"passed": True, "files": []}}]
    assert sum(call.args[0][1] == "--verify" for call in commands.call_args_list) == 1


def test_no_matching_packages_returns_an_empty_list(run_module):
    result = run_module({"name": ["not-installed"]}, {"name=not-installed": []})[0]
    assert result == []
