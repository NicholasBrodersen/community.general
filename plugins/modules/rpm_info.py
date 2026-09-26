#!/usr/bin/python
# Copyright (c) 2026, Nicholas Brodersen <nicholasbrodersen01@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r""""""

EXAMPLES = r""""""

RETURN = r""""""


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

        # deterministic return output
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

        filtered_rpm_headers = map(partial(filter_rpm_info, categories=self.vars.include), populated_rpm_headers)

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
