cmake_minimum_required(VERSION 3.3)

PROJECT(unetd C)


SET(SOURCES
	main.c network.c host.c service.c pex.c utils.c
	wg.c wg-user.c
)

SET(RUNSTATEDIR /var/run)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations -DRUNSTATEDIR="${RUNSTATEDIR}")
FIND_LIBRARY(libjson NAMES json-c json)

OPTION(UBUS_SUPPORT "enable ubus support" ON)
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	FIND_LIBRARY(nl nl-tiny)
	find_library(bpf NAMES bpf)
	SET(SOURCES ${SOURCES} wg-linux.c vxlan.c bpf.c rtnl.c)
ELSE()
	SET(nl "")
	SET(bpf "")
ENDIF()
IF(UBUS_SUPPORT)
  SET(SOURCES ${SOURCES} ubus.c)
  ADD_DEFINITIONS(-DUBUS_SUPPORT=1)
  FIND_LIBRARY(ubus ubus)
ELSE()
  SET(ubus "")
ENDIF()

ADD_LIBRARY(unet SHARED curve25519.c siphash.c sha512.c fprime.c f25519.c ed25519.c edsign.c)
TARGET_LINK_LIBRARIES(unet ubox)

ADD_EXECUTABLE(unetd ${SOURCES})
TARGET_LINK_LIBRARIES(unetd unet ubox ${ubus} blobmsg_json ${libjson} ${nl} ${bpf})

INSTALL(TARGETS unetd unet
	RUNTIME DESTINATION sbin
	LIBRARY DESTINATION lib
)
