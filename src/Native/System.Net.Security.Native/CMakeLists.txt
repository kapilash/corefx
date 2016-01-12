project(System.Net.Security.Native)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_definitions(-DPIC=1)

if(APPLE)
    add_definitions(-D__APPLE_USE_RFC_3542)
    add_definitions(-DTARGET_OS_MAC=1)
else()
   find_library(LIBGSS NAMES gssapi_krb5)
    add_definitions(-DTARGET_OS_MAC=0)
endif()



find_library(LIBGSS NAMES gssapi_krb5 PATHS /usr/lib/x86_64-linux-gnu/mit-krb5)  

if(LIBGSS STREQUAL LIBGSS-NOTFOUND)  

    message(SEND_ERROR "!!! Cannot find libkrb5-dev and System.Net.Security.Native cannot build without it. Try installing libkrb5-dev (or the appropriate package for your platform) !!!")  
    return()  
endif()  

find_library(HEIMDAL NAMES heimntlm)

if(HEIMDAL STREQUAL HEIMDAL-NOTFOUND)
    message(SEND_ERROR "!!! Cannot find heimdal-dev and System.Net.Security.Native cannot build without it. Try installing heimdal-dev (or the appropriate package for your platform) !!!")
    return()
endif()

set(NATIVENTLM_SOURCES
	pal_ntlmapi.cpp
)

set(NATIVEGSS_SOURCES
	pal_gssapi.cpp
)

include_directories(/usr/include)
include_directories(/usr/include/mit-krb5)
include_directories(/usr/include/heimdal)

add_library(System.Net.Security.Native
    SHARED
    ${NATIVENTLM_SOURCES}
    ${NATIVEGSS_SOURCES}
)


target_link_libraries(System.Net.Security.Native
	${HEIMDAL}
        ${LIBGSS} 
)

install (TARGETS System.Net.Security.Native DESTINATION .)
