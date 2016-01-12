project(System.Net.Security.Native)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_definitions(-DPIC=1)

if (APPLE)
   find_library(LIBGSS NAMES GSS)
   add_definitions(-DGSSFW)
   set(HEIMDAL "")
else()
   find_library(LIBGSS NAMES libgssapi_krb5)
   include_directories(/usr/include)
   include_directories(/usr/include/mit-krb5)
   include_directories(/usr/include/heimdal)
   find_library(HEIMDAL NAMES heimntlm)

    if(HEIMDAL STREQUAL HEIMDAL-NOTFOUND)
       message(SEND_ERROR "!!! Cannot find heimdal-dev and System.Net.Security.Native cannot build without it. Try installing heimdal-dev (or the appropriate package for your platform) !!!")
       return()
     endif()

endif()

if(LIBGSS STREQUAL LIBGSS-NOTFOUND)
    message(SEND_ERROR "!!! Cannot find libgssapi_krb5 and System.Net.Security.Native cannot build without it. Try installing libgssapi_krb5 (or the appropriate package for your platform) !!!")
    return()
endif()

set(NATIVEGSS_SOURCES
	pal_gssapi.cpp
)

set(NATIVENTLM_SOURCES
	pal_ntlmapi.cpp
)

if (APPLE)
   set (NETSECURITY_SOURCES     ${NATIVEGSS_SOURCES})
else()
      set (NETSECURITY_SOURCES     ${NATIVEGSS_SOURCES} ${NATIVENTLM_SOURCES})
endif()

add_library(System.Net.Security.Native
    SHARED
    ${NETSECURITY_SOURCES}
)

target_link_libraries(System.Net.Security.Native
	${LIBGSS}
)


target_link_libraries(System.Net.Security.Native
	${HEIMDAL}
        ${LIBGSS} 
)

install (TARGETS System.Net.Security.Native DESTINATION .)
