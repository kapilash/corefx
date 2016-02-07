project(System.Net.Security.Native)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_definitions(-DPIC=1)

find_library(LIB_HEIMNTLM NAMES heimntlm PATHS /usr/heimdal/lib)
include_directories(/usr/heimdal/include)

if(LIB_HEIMNTLM STREQUAL LIB_HEIMNTLM-NOTFOUND)
   message(FATAL_ERROR "Cannot find libheimntlm.so and System.Net.Security.Native cannot build without it. Try installing libheimntlm (or the appropriate package for your platform)")
endif()

add_definitions(-Wno-padded)

set(NATIVENTLM_SOURCES
     pal_ntlmapi.cpp
     pal_ntlm_utils.cpp
)

set(NTLMTEST_SOURCES
    NtlmTest.cpp
)

add_library(System.Net.Security.Native
   SHARED
   ${NATIVENTLM_SOURCES}
)

add_executable(NtlmTester
     ${NTLMTEST_SOURCES}
)

target_link_libraries(System.Net.Security.Native
    ${LIB_HEIMNTLM}
    ${OPENSSL_CRYPTO_LIBRARY}
)

target_link_libraries(NtlmTester
    ${LIB_HEIMNTLM}
    ${OPENSSL_CRYPTO_LIBRARY}
    System.Net.Security.Native
)

install (TARGETS System.Net.Security.Native DESTINATION .)

