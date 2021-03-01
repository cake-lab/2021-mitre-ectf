#!/bin/bash

# SED launcher script, with modifications for use in continuous integration testing (CIT)
# Based on SED launcher script written by Ben Janis

set -e

# launch controller
CONTROLLER=`docker run -d \
    -v ${SOCK_ROOT}:/socks ${CONT_DOCK_OPT} \
    ${DEPLOYMENT}/${SC}controller:${NAME}_${SCEWL_ID} \
    qemu-system-arm -M lm3s6965evb -nographic -monitor none \
        ${GDB} \
        -kernel /controller \
        -serial unix:/socks/scewl_bus_${SCEWL_ID}.sock,server \
        -serial unix:/socks/sss.sock \
        -serial unix:/socks/antenna_${SCEWL_ID}.sock`

# kill controller when CPU dies
trap "docker kill $CONTROLLER 2>/dev/null" EXIT

sleep 1

# launch CPU
docker run ${CPU_DOCK_OPT} \
    -v ${SOCK_ROOT}/sss.sock:/socks/sss.sock \
    -v ${SOCK_ROOT}/antenna_${SCEWL_ID}.sock:/socks/antenna.sock \
    -v ${SOCK_ROOT}/scewl_bus_${SCEWL_ID}.sock:/socks/scewl_bus.sock \
    ${DEPLOYMENT}/cpu:${NAME}_${SCEWL_ID} \
    qemu-arm -L /usr/arm-linux-gnueabi /cpu 2>&1 | tee ${SCEWL_ID}-cpu.log
