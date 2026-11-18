load("//rules/pavona:defs.bzl", "pavona_test")

def meter_id(name):
    """op/param/family/tier of acc_uov_<op>_<family>_<param>_<tier>_test, as the meters line prints them."""
    parts = name[len("acc_uov_"):-len("_test")].split("_")
    family = "_".join(parts[1:-2]) or "ldirect"
    return '-DMETER_ID="op={} param={} family={} tier={}"'.format(parts[0], parts[-2], family, parts[-1])

def uov_test(name, copts = [], srcs = [], **kwargs):
    """pavona_test that also defines METER_ID from the target name (unless the cell sets it)."""
    if name.startswith("acc_uov_") and name.endswith("_test") and not [c for c in copts if "METER_ID" in c]:
        copts = copts + [meter_id(name)]
    pavona_test(name = name, copts = copts, srcs = srcs + ["acc_dmem_copy.h"], **kwargs)
