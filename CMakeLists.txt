cmake_minimum_required(VERSION 3.10)
project(sshfs VERSION 3.7.3 LANGUAGES C)

# Build type
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Compiler flags
add_compile_options(-D_REENTRANT -DHAVE_CONFIG_H -Wall -Wextra -Wno-sign-compare -Wmissing-declarations -Wwrite-strings -Wno-unused-parameter)

# Compiler check
include(CheckCSourceCompiles)

check_c_source_compiles("
__attribute__((warn_unused_result)) int get_4() { return 4; }
int main(void) { (void)get_4(); return 0; }
" COMPILER_GIVES_UNUSED_RESULT_WARNING)

if(COMPILER_GIVES_UNUSED_RESULT_WARNING)
    add_compile_options(-Wno-unused-result)
endif()

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_search_module(FUSE3 REQUIRED fuse3>=3.1.0)
pkg_search_module(GLIB REQUIRED glib-2.0)
pkg_search_module(GTHREAD REQUIRED gthread-2.0)

# Sources and platform-specific adjustments
set(PACKAGE_VERSION ${PROJECT_VERSION})
set(SOURCES sshfs.c cache.c)
if(APPLE)
  list(APPEND SOURCES compat/fuse_opt.c compat/darwin_compat.c)
  include_directories(compat)
  set(IDMAP_DEFAULT use')
else()
  set(IDMAP_DEFAULT none)
endif()
configure_file(config.h.in config.h)

# Executable target
add_executable(sshfs ${SOURCES})
target_include_directories(sshfs PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${FUSE3_INCLUDE_DIRS} ${GLIB_INCLUDE_DIRS} ${GTHREAD_INCLUDE_DIRS})
target_compile_definitions(sshfs PRIVATE -DFUSE_USE_VERSION=31)
target_link_libraries(sshfs ${FUSE3_LIBRARIES} ${GLIB_LIBRARIES} ${GTHREAD_LIBRARIES})
install(TARGETS sshfs DESTINATION bin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h DESTINATION include)

# Creating links
# Assuming `sbindir` and `bindir` are determined or set previously in your CMakeLists.txt
set(sbindir "${CMAKE_INSTALL_PREFIX}/sbin")
set(bindir "${CMAKE_INSTALL_PREFIX}/bin")

# Then, use the install(CODE ...) command to execute your script with these arguments
install(CODE "execute_process(COMMAND bash \"${CMAKE_CURRENT_SOURCE_DIR}/utils/install_helper.sh\" \"${sbindir}\" \"${bindir}\")")

# Optional manual page generation (requires conditional checks in CMake)
find_program(RST2MAN rst2man)

if(NOT RST2MAN)
  message(WARNING "rst2man not found. Man pages will not be generated.")
else()
  # Define the input and output files
  set(MAN_PAGE_INPUT "${CMAKE_CURRENT_SOURCE_DIR}/sshfs.rst")
  set(MAN_PAGE_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/sshfs.1")

  # Add a custom command to generate the man page
  add_custom_command(
    OUTPUT ${MAN_PAGE_OUTPUT}
    COMMAND ${RST2MAN} ${MAN_PAGE_INPUT} ${MAN_PAGE_OUTPUT}
    DEPENDS ${MAN_PAGE_INPUT}
    COMMENT "Generating man page: sshfs.1"
  )

  # Add a custom target to trigger the custom command
  add_custom_target(manpages ALL DEPENDS ${MAN_PAGE_OUTPUT})

  # Install the man page
  install(FILES ${MAN_PAGE_OUTPUT} DESTINATION share/man/man1)
endif()
