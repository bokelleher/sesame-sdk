# vcpkg overlay port for the SESAME C++ SDK.
#
# Use it today with:
#   vcpkg install sesame-esam --overlay-ports=<repo>/cpp/ports
# then in your project: find_package(sesame CONFIG REQUIRED)
#                       target_link_libraries(app PRIVATE sesame::sesame)
#
# SHA512 is pinned to the cpp-v0.1.2 tag's source archive. Update REF + SHA512
# (run `vcpkg install` once to have it print the correct hash) when bumping.

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO bokelleher/sesame-sdk
    REF cpp-v0.1.2
    SHA512 b8d3368db0662dc12b3e02e3f016d7cadd4955430ea94303a84aa1c39fa95735e8251575b3366f3b18233ce7f80d769a50428b6c7eec0c1d2cf24f9f3c633338
    HEAD_REF main
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/cpp"
    OPTIONS
        -DSESAME_BUILD_TESTS=OFF
        -DSESAME_BUILD_EXAMPLES=OFF
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME sesame CONFIG_PATH lib/cmake/sesame)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST
    "${SOURCE_PATH}/LICENSE-MIT"
    "${SOURCE_PATH}/LICENSE-APACHE")
