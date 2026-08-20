# vcpkg overlay port for the SESAME C++ SDK.
#
# Use it today with:
#   vcpkg install sesame-esam --overlay-ports=<repo>/cpp/ports
# then in your project: find_package(sesame CONFIG REQUIRED)
#                       target_link_libraries(app PRIVATE sesame::sesame)
#
# SHA512 is pinned to the cpp-v0.1.4 tag's source archive. Update REF + SHA512
# (run `vcpkg install` once to have it print the correct hash) when bumping.

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO bokelleher/sesame-sdk
    REF cpp-v0.1.4
    SHA512 58601c7c3b880dfafb30460348dcd779182a75b9f3155d1d2b60e4e92868ca42896b3f968f78f832ab2e3313d37be3f738d16a4382e2d695b9e77653a9f9b982
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
