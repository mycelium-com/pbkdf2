cmake_minimum_required(VERSION 3.9)
project(pbkdf VERSION 1.0.0 DESCRIPTION "Password-based key derivation library")

if (NOT TARGET hashing)
# Hashing functions library
add_subdirectory(extras/hashing)
endif()

set(pbkdf_src
   src/pbkdf.c
)

add_library(pbkdf ${pbkdf_src})

target_include_directories(pbkdf PRIVATE include)
target_include_directories(pbkdf PRIVATE extras/hashing/include)

set_target_properties(pbkdf PROPERTIES
   VERSION ${PROJECT_VERSION}
   POSITION_INDEPENDENT_CODE 1
   PUBLIC_HEADER "include/pbkdf.h"
)

add_executable(test_pbkdf2_sha2 misc/pbkdf2_test_sha2.c)
add_executable(test_pbkdf2_sha3 misc/pbkdf2_test_sha3.c)

target_include_directories(test_pbkdf2_sha2 PRIVATE include)
target_include_directories(test_pbkdf2_sha3 PRIVATE include)

target_link_libraries(test_pbkdf2_sha2 hashing pbkdf)
target_link_libraries(test_pbkdf2_sha3 hashing pbkdf)

include(GNUInstallDirs)
install(TARGETS pbkdf
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(pbkdf.pc.in pbkdf.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/pbkdf.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
