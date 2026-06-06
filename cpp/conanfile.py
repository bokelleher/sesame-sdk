from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import copy
import os


class SesameEsamConan(ConanFile):
    name = "sesame-esam"
    version = "0.1.0"
    license = "MIT OR Apache-2.0"
    homepage = "https://github.com/bokelleher/sesame-sdk"
    url = "https://github.com/bokelleher/sesame-sdk"
    description = (
        "Native C++ implementation of SESAME, the proposed SCTE 130-9 security "
        "layer for the ESAM interface (HMAC auth, channel-scoped authorization, "
        "AES-256-GCM payload encryption). Imported as find_package(sesame)."
    )
    topics = ("scte", "esam", "sesame", "hmac", "aes-gcm", "cryptography", "ad-insertion")
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    # The recipe lives in cpp/; export the C++ tree plus the repo-root licenses.
    exports_sources = (
        "CMakeLists.txt",
        "cmake/*",
        "include/*",
        "src/*",
        "../LICENSE-MIT",
        "../LICENSE-APACHE",
    )

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def requirements(self):
        self.requires("openssl/[>=3.0 <4]")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["SESAME_BUILD_TESTS"] = "OFF"
        tc.variables["SESAME_BUILD_EXAMPLES"] = "OFF"
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        for lic in ("LICENSE-MIT", "LICENSE-APACHE"):
            copy(self, lic, src=os.path.join(self.export_sources_folder, ".."),
                 dst=os.path.join(self.package_folder, "licenses"))

    def package_info(self):
        self.cpp_info.libs = ["sesame"]
        # Consumers use find_package(sesame) and link sesame::sesame.
        self.cpp_info.set_property("cmake_file_name", "sesame")
        self.cpp_info.set_property("cmake_target_name", "sesame::sesame")
        self.cpp_info.requires = ["openssl::crypto"]
