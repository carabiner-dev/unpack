# The project's own module, dressing up the lookup of yaml-cpp.
find_package(PkgConfig QUIET)
find_package(yaml-cpp CONFIG QUIET)
pkg_check_modules(PC_YAML yaml-cpp>=0.6)
