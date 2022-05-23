cmake_minimum_required(VERSION 3.3)

PROJECT(unetd C)


SET(SOURCES
	main.c network.c host.c service.c pex.c utils.c
	curve25519.c siphash.c
	wg.c wg-dummy.c wg-user.c
)

SET(RUNSTATEDIR /var/run)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations -DRUNSTATEDIR="${RUNSTATEDIR}")
FIND_LIBRARY(libjson NAMES json-c json)

OPTION(UBUS_SUPPORT "enable ubus support" ON)
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	FIND_LIBRARY(nl nl-tiny)
	SET(SOURCES ${SOURCES} wg-linux.c)
ELSE()
	SET(nl "")
ENDIF()
IF(UBUS_SUPPORT)
  SET(SOURCES ${SOURCES} ubus.c)
  ADD_DEFINITIONS(-DUBUS_SUPPORT=1)
  FIND_LIBRARY(ubus ubus)
ELSE()
  SET(ubus "")
ENDIF()

ADD_EXECUTABLE(unetd ${SOURCES})
TARGET_LINK_LIBRARIES(unetd ubox ${ubus} blobmsg_json ${libjson} ${nl})

INSTALL(TARGETS unetd
	RUNTIME DESTINATION sbin
	LIBRARY DESTINATION lib
)
