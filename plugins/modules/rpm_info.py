#!/usr/bin/python
# Copyright (c) 2026, Nicholas Brodersen <nicholasbrodersen01@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: rpm_info
short_description: Retrieve installed RPM package and package verification information
version_added: 13.5.0
description:
- Retrieves information about installed RPM packages.
- Returns selected RPM tags and optionally reports file verification results for each package.
author:
- Nicholas Brodersen (@NicholasBrodersen)
extends_documentation_fragment:
- community.general._attributes
- community.general._attributes.info_module
requirements:
- The rpm executable must be installed on the managed host.
- The getcap executable is optional. Used to collect current capabilities when RPM reports a capabilities
  verification problem.
options:
  name:
    description:
    - Package name to query RPM package or packages info.
    - Each entry is passed to RPM as C(name=SELECTOR). Matching follows RPM's native name pattern rules.
    - Use V(*) to query all installed packages. Quote patterns containing an asterisk in YAML.
    type: list
    elements: str
    required: true
  include:
    description:
    - Categories of RPM tags to return for each package.
    - V(metadata) includes package identity, descriptions, build and installation information, and package sizes.
    - V(files) includes file paths and file metadata as RPM tag arrays.
    - V(dependencies) includes provided capabilities, requirements, conflicts, obsoletes, and other dependency relationships.
    - V(scripts) includes script bodies, interpreters, and script flags. The scripts are not executed.
    - V(triggers) includes package, file, and transaction file trigger information.
    - V(signatures) includes stored signatures and digest metadata.
    - V(changelog) includes changelog timestamps, authors, and entries.
    - V(all) selects every category, including V(changelog).
    - The package name is always returned. An empty list returns only the name and, when O(verify=true), verification
      results.
    - Optional tags are omitted when unsupported by the installed RPM version or absent from the package header.
      The metadata fields C(epoch) and C(arch) use V(null) when absent.
    type: list
    elements: str
    choices:
    - all
    - changelog
    - dependencies
    - files
    - metadata
    - scripts
    - signatures
    - triggers
    default:
    - dependencies
    - files
    - metadata
    - scripts
    - signatures
    - triggers
  verify:
    description:
    - Runs RPM file verification for each matching package and returns a C(verify) dictionary with the results.
    - Verification is performed even when V(files) is not selected by O(include).
    - Checks reported by RPM include size, mode, digest, device, symbolic link target, owner, group, modification
      time, and capabilities.
    - Dependency checks, verification scripts, and package header digest and signature checks are disabled. File
      digest checks remain enabled.
    - Reported file differences or unavailable checks set C(verify.passed) to V(false).
    - Command failures without interpretable file failures, or output that cannot be interpreted, fail the task.
    type: bool
    default: false
notes:
- Requires access to the installed RPM database. Reading protected files for verification can require privilege
  escalation.
- Results are returned in C(packages) and are not automatically added to C(ansible_facts).
- Package identities are deduplicated and sorted by by name, epoch, version, release, and architecture.
- RPM tag names are converted to lowercase. Integer XML values become integers, string values remain strings, and
  binary values are returned as base64 text with whitespace removed.
- Array tags remain lists even when they contain one value. Raw RPM flags and timestamps are not reformatted. structured
  mode, device, and timestamp values are provided inside verification failures.
- Unavailable getcap details are reported in the affected capabilities failure. Missing getcap does not prevent
  ordinary package queries.
"""

EXAMPLES = r"""
- name: Retrieve the default information for an installed package
  community.general.rpm_info:
    name:
      - rpm
  register: rpm_packages

- name: Query package names using RPM native patterns
  community.general.rpm_info:
    name:
      - 'python3*'
      - 'lib*'
    include:
      - metadata
      - dependencies
  register: matching_packages

- name: Retrieve every available category, including changelogs
  community.general.rpm_info:
    name:
      - '*'
    include:
      - all
  register: installed_packages

- name: Retrieve file metadata arrays for bash
  community.general.rpm_info:
    name:
      - bash
    include:
      - metadata
      - files
  register: bash_packages

- name: Verify bash files and return package metadata
  become: true
  community.general.rpm_info:
    name:
      - bash
    include:
      - metadata
    verify: true
  register: verified_packages

- name: Require an installed matching package and successful verification
  ansible.builtin.assert:
    that:
      - verified_packages.packages | length > 0
      - verified_packages.packages | rejectattr('verify.passed') | list | length == 0

- name: Return only package names and verification results
  become: true
  community.general.rpm_info:
    name:
      - 'openssh*'
    include: []
    verify: true
  register: verification_only
"""

RETURN = r"""
packages:
  description:
    - Matching installed packages. Returns an empty list when no package names match.
    - Each package is a flat dictionary. O(include) selects fields, rather than creating category dictionaries.
    - Additional fields use lowercase RPM tag names and depend on the selected categories, RPM version, and package header.
    - V(metadata) includes fields such as C(summary), C(license), and C(buildtime).
    - V(files) includes fields such as C(filenames), C(filemodes), and C(filedigests).
    - V(dependencies) includes fields such as C(providename), C(requirename), and C(requireversion).
    - V(scripts) includes fields such as C(prein), C(postin), and C(postinprog).
    - V(triggers) includes fields such as C(triggername), C(triggerscripts), and C(filetriggername).
    - V(signatures) includes fields such as C(sigpgp), C(sigmd5), and C(sha256header).
    - V(changelog) includes C(changelogtime), C(changelogname), and C(changelogtext).
    - V(all) selects all categories supported by this module. It does not request every tag known to RPM.
    - Scalar tags contain strings or integers. Array tags remain lists, including when they contain only one value.
    - Binary values are base64 strings with whitespace removed. Numeric RPM flags and timestamps remain integers.
    - Unsupported or absent tags are omitted, except for the documented nullable identity fields.
    - Packages are deduplicated and sorted by name, epoch, version, release, and architecture before output filtering.
    - The sample shows an abbreviated metadata result.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description: Package name. Included regardless of O(include).
      type: str
      returned: always
    epoch:
      description: Package epoch as an integer, or V(null) when absent. A stored zero remains zero.
      type: raw
      returned: when O(include) contains V(metadata) or V(all)
    version:
      description: Package version.
      type: str
      returned: when O(include) contains V(metadata) or V(all)
    release:
      description: Package release.
      type: str
      returned: when O(include) contains V(metadata) or V(all)
    arch:
      description: Package architecture as a string, or V(null) when absent.
      type: raw
      returned: when O(include) contains V(metadata) or V(all)
    verify:
      description:
        - File verification results, independent of the categories selected by O(include).
        - Reported differences or unavailable checks do not by themselves fail the Ansible task.
      type: dict
      returned: when O(verify=true)
      contains:
        passed:
          description: Whether RPM exited successfully and no file verification failures were recorded.
          type: bool
          returned: always
        files:
          description:
            - Files with reported verification problems. Empty when no file failures were recorded.
            - Passing files and state-only records with no failed checks are omitted.
          type: list
          elements: dict
          returned: always
          contains:
            path:
              description: Absolute package file path, excluding any appended RPM diagnostic message.
              type: str
            result:
              description:
                - RPM status token, either V(missing) or a nine-character verification result.
                - Positions represent size, mode, digest, device, link target, owner, group, modification time, and capabilities.
                - Their failure markers are C(S), C(M), C(5), C(D), C(L), C(U), C(G), C(T), and C(P), respectively.
                - C(?) means RPM could not perform the check. C(.) means no failure was reported for that check.
              type: str
            attribute:
              description: File attribute marker reported by RPM.
              type: dict
              returned: when RPM supplies an attribute marker
              contains:
                code:
                  description: Single-character attribute marker.
                  type: str
                  choices: [a, c, d, g, l, m, n, r, s]
                name:
                  description:
                    - Readable attribute name corresponding to C(code).
                    - The mappings are C(a=artifact), C(c=configuration), C(d=documentation), C(g=ghost),
                      C(l=license), C(m=missing_ok), C(n=configuration_noreplace), C(r=readme), and C(s=spec).
                  type: str
            message:
              description: Appended RPM diagnostic or state messages, joined with a semicolon and a space.
              type: str
              returned: when RPM appends messages to the record
            failures:
              description:
                - Dictionary keyed by the checks described below. Only relevant entries are included.
                - Each entry contains C(expected) and C(actual). An optional C(error) string explains unavailable checks,
                  collection errors, or conflicting observations.
                - Current values are collected after RPM finishes and may differ from what RPM observed.
                - A current value may be available even when RPM reported that its check could not be performed.
                - If the path is reported missing or its metadata cannot be read, only C(exists) is included.
              type: dict
              contains:
                exists:
                  description:
                    - Path existence or metadata access problem. C(expected) is always V(true).
                    - For V(missing) records, C(actual) is V(false) when absence is confirmed, V(true) when the path now
                      exists, or V(null) when another error prevents the existence check.
                    - For other records whose metadata cannot be read, C(actual) is V(null).
                  type: dict
                size:
                  description: C(expected) and C(actual) are integer file sizes in bytes.
                  type: dict
                mode:
                  description:
                    - C(expected) and C(actual) are dictionaries containing C(permissions), an octal string such as
                      V(0644), and C(symbolic), a file type and permissions string such as V(-rw-r--r--).
                    - When these dictionaries are equal, a C(note) string explains that RPM can also detect non-default ACLs.
                  type: dict
                digest:
                  description:
                    - C(expected) is the stored file digest string. C(actual) is the computed hexadecimal digest,
                      or V(null) when the digest cannot be calculated.
                    - C(algorithm) contains the integer C(id) and string C(name). The name is V(null) for an unknown algorithm.
                    - An omitted RPM algorithm identifier uses C(id=0) and C(name=md5).
                  type: dict
                device:
                  description:
                    - C(expected) and C(actual) are dictionaries containing the integer fields C(raw), C(major),
                      and C(minor) for the device number.
                  type: dict
                link_target:
                  description:
                    - C(expected) and C(actual) are symbolic link target strings.
                    - C(actual) is V(null) when the target cannot be read.
                  type: dict
                user:
                  description:
                    - C(expected) is the stored owner name. C(actual) is the current owner name, or the integer UID
                      when the name cannot be resolved.
                    - C(actual_uid) always contains the current integer UID.
                  type: dict
                group:
                  description:
                    - C(expected) is the stored group name. C(actual) is the current group name, or the integer GID
                      when the name cannot be resolved.
                    - C(actual_gid) always contains the current integer GID.
                  type: dict
                mtime:
                  description:
                    - C(expected) and C(actual) contain C(epoch), an integer Unix timestamp in seconds, and C(iso),
                      an ISO 8601 timestamp string in UTC. Fractional seconds are discarded from the current timestamp.
                  type: dict
                capabilities:
                  description:
                    - C(expected) is the stored capabilities string, or an empty string when none are recorded.
                    - C(actual) is the capabilities string reported by C(getcap), an empty string when none are reported,
                      or V(null) when C(getcap) is unavailable or collection fails.
                  type: dict
        messages:
          description: Lines written to standard error by RPM during verification.
          type: list
          elements: str
          returned: when RPM writes nonblank standard error
      sample:
        passed: false
        files:
          - path: /etc/example.conf
            result: S........
            attribute:
              code: c
              name: configuration
            failures:
              size:
                expected: 128
                actual: 160
          - path: /usr/share/example/data
            result: missing
            failures:
              exists:
                expected: true
                actual: false
  sample:
    - name: example
      epoch: null
      version: "1.0"
      release: "1"
      arch: noarch
"""

from functools import partial
from itertools import chain

from ansible_collections.community.general.plugins.module_utils._module_helper import ModuleHelper
from ansible_collections.community.general.plugins.module_utils._rpm_info import (
    ALL_SECTIONS,
    DEFAULT_SECTIONS,
    RPMCLI,
    filter_rpm_info,
    get_rpm_results,
    normalize_rpm_info,
    populate_rpm_info,
)


class RPMInfoModule(ModuleHelper):
    module = dict(
        argument_spec=dict(
            name=dict(
                type="list",
                elements="str",
                required=True,
            ),
            include=dict(
                type="list",
                elements="str",
                choices=sorted(ALL_SECTIONS | {"all"}),
                default=sorted(DEFAULT_SECTIONS),
            ),
            verify=dict(
                type="bool",
                default=False,
            ),
        ),
        supports_check_mode=True,
    )

    def __init_module__(self):
        self.rpm_cli = RPMCLI(self.module)

        if "all" in self.vars.include:
            self.vars.include = ALL_SECTIONS

        self.return_info = []

    def __run__(self):
        rpms = map(
            partial(get_rpm_results, rpm_cli=self.rpm_cli),
            self.vars.name,
        )

        rpm_headers = chain.from_iterable(rpms)

        deduplicated_rpm_headers = {
            (
                header["NAME"],
                header["EPOCH"],
                header["VERSION"],
                header["RELEASE"],
                header["ARCH"],
            ): header
            for header in rpm_headers
        }.values()

        # done for deterministic return output
        sorted_rpm_headers = sorted(
            deduplicated_rpm_headers,
            key=lambda header: (
                header["NAME"],
                header.get("EPOCH") or 0,
                header["VERSION"],
                header["RELEASE"],
                header.get("ARCH") or "",
            ),
        )

        populated_rpm_headers = map(
            partial(populate_rpm_info, self.rpm_cli, verify=self.vars.verify),
            sorted_rpm_headers,
        )

        filtered_rpm_headers = map(
            partial(filter_rpm_info, categories=self.vars.include),
            populated_rpm_headers
        )

        normalized_filtered_rpm_headers = map(normalize_rpm_info, filtered_rpm_headers)

        self.return_info = list(normalized_filtered_rpm_headers)

    def __quit_module__(self):
        self.update_output(
            packages=self.return_info,
        )


def main():
    RPMInfoModule().run()


if __name__ == "__main__":
    main()
