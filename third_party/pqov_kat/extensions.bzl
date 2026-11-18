# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""pqov KATs; only the pkc-skc configs the ACC implements.

From the round2 and round3 releases of https://github.com/pqov/pqov, one archive
per parameter set; the .rsp files match pqov's SHA256SUMS at the tagged commit.
Round-3 Is equals round-2 Is; round-3 Ip is called Ip3 here.
"""

_RELEASE = "https://github.com/pqov/pqov/releases/download/{0}/uov-{0}-{1}-pkc-skc-KAT.tar.xz"

# name -> (release, pqov parameter set, sha256 of the archive)
_KATS = {
    "Ip": ("round2", "Ip", "216e0b9288f07c862dbf5bcce767f1fd61d9dfb361df73907b479b7cbfa70e4f"),
    "Is": ("round2", "Is", "8d11a4bd67fdb584205b48768a0afd4524bd35c6e7d5324c621f94f54a3545cd"),
    "Ip3": ("round3", "Ip", "ab378939badff90f9860f9e040518d48c311a2bfb5f625809aef480be75c6782"),
}

_BUILD = """\
package(default_visibility = ["//visibility:public"])
""" + "".join([
    """
filegroup(
    name = "{0}_pkc_skc",
    srcs = ["{1}/KAT/{2}-pkc-skc/PQCsignKAT_32.rsp"],
)
""".format(name, release, param)
    for name, (release, param, _sha) in _KATS.items()
])

def _pqov_kat_impl(rctx):
    for release, param, sha in _KATS.values():
        rctx.download_and_extract(
            url = _RELEASE.format(release, param),
            output = release,
            sha256 = sha,
        )
    rctx.file("BUILD.bazel", _BUILD)

_pqov_kat_repo = repository_rule(implementation = _pqov_kat_impl)

pqov_kat = module_extension(
    implementation = lambda _: _pqov_kat_repo(name = "pqov_kat"),
)
