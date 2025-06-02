cmake_minimum_required(VERSION 3.10)

PROJECT(unetd C)


SET(SOURCES
	main.c network.c host.c service.c
	pex.c pex-stun.c
	wg.c wg-user.c
)

SET(RUNSTATEDIR /var/run)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations -DRUNSTATEDIR="${RUNSTATEDIR}")
FIND_LIBRARY(libjson NAMES json-c json)

OPTION(UBUS_SUPPORT "enable ubus support" ON)
OPTION(VXLAN_SUPPORT "enable VXLAN support" ON)
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	FIND_LIBRARY(nl nl-tiny)
	SET(SOURCES ${SOURCES} wg-linux.c)
ELSE()
	SET(nl "")
	SET(VXLAN_SUPPORT OFF)
ENDIF()
IF(VXLAN_SUPPORT)
	find_library(bpf NAMES bpf)
	find_library(elf NAMES elf)
	find_library(zlib NAMES z)
	SET(SOURCES ${SOURCES} bpf.c vxlan.c rtnl.c)
	ADD_DEFINITIONS(-DVXLAN_SUPPORT)
ELSE()
	SET(bpf "")
	SET(elf "")
	SET(zlib "")
ENDIF()

IF(UBUS_SUPPORT)
  SET(SOURCES ${SOURCES} ubus.c enroll.c token.c)
  SET(DHT_SOURCES ${DHT_SOURCES} udht-ubus.c)
  ADD_DEFINITIONS(-DUBUS_SUPPORT=1)
  FIND_LIBRARY(ubus ubus)
  FIND_LIBRARY(udebug NAMES udebug)
ELSE()
  SET(ubus "")
  SET(udebug "")
ENDIF()

ADD_LIBRARY(unet SHARED curve25519.c siphash.c sha512.c fprime.c f25519.c ed25519.c edsign.c auth-data.c chacha20.c pex-msg.c utils.c stun.c random.c)
TARGET_LINK_LIBRARIES(unet ubox)

ADD_EXECUTABLE(unetd ${SOURCES})
TARGET_LINK_LIBRARIES(unetd unet ubox ${ubus} blobmsg_json ${libjson} ${nl} ${bpf} ${elf} ${zlib} ${udebug})

ADD_EXECUTABLE(unet-tool cli.c)
TARGET_LINK_LIBRARIES(unet-tool unet blobmsg_json ${libjson} ubox)

ADD_EXECUTABLE(unet-dht dht.c udht.c ${DHT_SOURCES})
TARGET_LINK_LIBRARIES(unet-dht unet ${ubus} ubox)

INSTALL(TARGETS unetd unet unet-tool unet-dht
	RUNTIME DESTINATION sbin
	LIBRARY DESTINATION lib
)
