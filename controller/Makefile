#  2021 Collegiate eCTF
#  SCEWL Bus Controller Makefile
#  Ben Janis
#
#  (c) 2021 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!


# define the part type and base directory - must be defined for makedefs to work
PART=LM3S6965
ROOT=.

# include the common make definitions
include lm3s/makedefs

# add additional directories to search for source files to VPATH
VPATH=lm3s

# add additional directories to search for header files to IPATH
IPATH=${ROOT}
IPATH+=${ROOT}/CMSIS/Include
IPATH+=${VPATH}

# add flags to pass to the compiler
CFLAGS+=-DSCEWL_ID=${SCEWL_ID}
CFLAGS+=-O1

ifdef DEBUG_LEVEL
CFLAGS+=-DDEBUG_LEVEL=${DEBUG_LEVEL}
endif

# this rule must come first in `all`
all: ${COMPILER}

# for each source file that needs to be compiled besides
# the file that defines `main`, add the next two lines 
LDFLAGS+=${COMPILER}/scewl.o
all: ${COMPILER}/scewl.o
LDFLAGS+=${COMPILER}/interface.o
all: ${COMPILER}/interface.o
LDFLAGS+=${COMPILER}/flash_buffers.o
all: ${COMPILER}/flash_buffers.o
LDFLAGS+=${COMPILER}/sed_secrets.o
all: ${COMPILER}/sed_secrets.o
LDFLAGS+=${COMPILER}/sed_rand.o
all: ${COMPILER}/sed_rand.o
LDFLAGS+=${COMPILER}/timers.o
all: ${COMPILER}/timers.o
LDFLAGS+=${COMPILER}/broadcast.o
all: ${COMPILER}/broadcast.o
LDFLAGS+=${COMPILER}/dtls.o
all: ${COMPILER}/dtls.o


############# start masked-aes-c ##############
MASKED_AES_PATH=./masked-aes-c
VPATH+=${MASKED_AES_PATH}
IPATH+=${MASKED_AES_PATH}

LDFLAGS+=${COMPILER}/masked_aes.o

all: ${COMPILER}/masked_aes.o
############### end masked-aes-c ##############

################ start mbedtls ################
# Modified mbedtls library
MBEDTLS_CUSTOM_PATH=./mbedtls_custom
VPATH+=${MBEDTLS_CUSTOM_PATH}/library
IPATH+=${MBEDTLS_CUSTOM_PATH}/include

# Standard mbedtls library
MBEDTLS_PATH=./mbedtls
VPATH+=${MBEDTLS_PATH}/library
IPATH+=${MBEDTLS_PATH}/include
CFLAGS+=-DMBEDTLS_CONFIG_FILE='"mbedtls-config.h"'

LDFLAGS+=${COMPILER}/aes.o
LDFLAGS+=${COMPILER}/asn1parse.o
LDFLAGS+=${COMPILER}/base64.o
LDFLAGS+=${COMPILER}/bignum.o
LDFLAGS+=${COMPILER}/certs.o
LDFLAGS+=${COMPILER}/cipher.o
LDFLAGS+=${COMPILER}/cipher_wrap.o
LDFLAGS+=${COMPILER}/debug.o
LDFLAGS+=${COMPILER}/des.o
LDFLAGS+=${COMPILER}/error.o
LDFLAGS+=${COMPILER}/gcm.o
LDFLAGS+=${COMPILER}/hmac_drbg.o
LDFLAGS+=${COMPILER}/md.o
LDFLAGS+=${COMPILER}/md5.o
LDFLAGS+=${COMPILER}/memory_buffer_alloc.o
LDFLAGS+=${COMPILER}/oid.o
LDFLAGS+=${COMPILER}/pem.o
LDFLAGS+=${COMPILER}/pk.o
LDFLAGS+=${COMPILER}/pkparse.o
LDFLAGS+=${COMPILER}/pk_wrap.o
LDFLAGS+=${COMPILER}/platform.o
LDFLAGS+=${COMPILER}/platform_util.o
LDFLAGS+=${COMPILER}/rsa.o
LDFLAGS+=${COMPILER}/rsa_internal.o
LDFLAGS+=${COMPILER}/sha1.o
LDFLAGS+=${COMPILER}/sha256.o
LDFLAGS+=${COMPILER}/ssl_cache.o
LDFLAGS+=${COMPILER}/ssl_ciphersuites.o
LDFLAGS+=${COMPILER}/ssl_cli.o
LDFLAGS+=${COMPILER}/ssl_cookie.o
LDFLAGS+=${COMPILER}/ssl_msg.o
LDFLAGS+=${COMPILER}/ssl_srv.o
LDFLAGS+=${COMPILER}/ssl_tls.o
LDFLAGS+=${COMPILER}/timing.o
LDFLAGS+=${COMPILER}/x509.o
LDFLAGS+=${COMPILER}/x509_crt.o

all: ${COMPILER}/aes.o
all: ${COMPILER}/asn1parse.o
all: ${COMPILER}/base64.o
all: ${COMPILER}/bignum.o
all: ${COMPILER}/certs.o
all: ${COMPILER}/cipher.o
all: ${COMPILER}/cipher_wrap.o
all: ${COMPILER}/ctr_drbg.o
all: ${COMPILER}/debug.o
all: ${COMPILER}/des.o
all: ${COMPILER}/error.o
all: ${COMPILER}/gcm.o
all: ${COMPILER}/hmac_drbg.o
all: ${COMPILER}/md.o
all: ${COMPILER}/md5.o
all: ${COMPILER}/memory_buffer_alloc.o
all: ${COMPILER}/oid.o
all: ${COMPILER}/pem.o
all: ${COMPILER}/pk.o
all: ${COMPILER}/pkparse.o
all: ${COMPILER}/pk_wrap.o
all: ${COMPILER}/platform.o
all: ${COMPILER}/platform_util.o
all: ${COMPILER}/rsa.o
all: ${COMPILER}/rsa_internal.o
all: ${COMPILER}/sha1.o
all: ${COMPILER}/sha256.o
all: ${COMPILER}/ssl_cache.o
all: ${COMPILER}/ssl_ciphersuites.o
all: ${COMPILER}/ssl_cli.o
all: ${COMPILER}/ssl_cookie.o
all: ${COMPILER}/ssl_msg.o
all: ${COMPILER}/ssl_srv.o
all: ${COMPILER}/ssl_tls.o
all: ${COMPILER}/timing.o
all: ${COMPILER}/x509.o
all: ${COMPILER}/x509_crt.o
################ end mbedtls ################

################ start printf ################
PRINTF_PATH=./printf
VPATH+=${PRINTF_PATH}
IPATH+=${PRINTF_PATH}
LDFLAGS+=${COMPILER}/printf.o
all: ${COMPILER}/printf.o
################ end printf ################

# this must be the last build rule of `all`
all: ${COMPILER}/controller.axf

# clean all build products
clean:
	@rm -rf ${COMPILER} ${wildcard *~}

# create the output directory
${COMPILER}:
	@mkdir ${COMPILER}

# check that SCEWL_ID is defined
check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1)))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1))
arg_check:
	$(call check_defined, SCEWL_ID)

${COMPILER}/controller.axf: arg_check
${COMPILER}/controller.axf: ${COMPILER}/controller.o
${COMPILER}/controller.axf: ${COMPILER}/startup_${COMPILER}.o
${COMPILER}/controller.axf: ${COMPILER}/system_lm3s.o
ifeq (${COMPILER}, gcc)
${COMPILER}/controller.axf: lm3s/controller.ld
endif
SCATTERgcc_controller=lm3s/controller.ld
ifeq (${COMPILER}, sourcerygxx)
${COMPILER}/controller.axf: controller_sourcerygxx.ld
endif
SCATTERsourcerygxx_controller=lm3s6965-rom.ld -T controller_sourcerygxx.ld
ENTRY_controller=Reset_Handler

#
# Include the automatically generated dependency files.
#
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif
