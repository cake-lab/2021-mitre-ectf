# 2021 Collegiate eCTF
# Generate SED secrets Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

# load current SSS container to modify
ARG DEPLOYMENT
FROM ${DEPLOYMENT}/sss

ARG SCEWL_ID

# NOTE: only sss/ and its subdirectories in the repo are accessible to this Dockerfile as .
# NOTE: to maximize the useage of container cache, use ADD to map in only the files/directories you need
#       (e.g. only mapping in the SED directory rather than the entire repo)

# do here whatever you need here to create secrets for the new SED that the SSS needs access to

# Create SED-specific secrets directory
RUN mkdir /secrets/${SCEWL_ID}


# Generate provisioning key and certificate request for SED validation during registration
RUN openssl genrsa -out /secrets/${SCEWL_ID}/sed.key 2048
RUN openssl req -new -key /secrets/${SCEWL_ID}/sed.key -out /secrets/${SCEWL_ID}/sed.csr -config /secrets/configs/sed_crt.cfg -subj "/CN=${SCEWL_ID}_PROVISION"

# Sign provisioning certificate for SED
RUN openssl x509 -req -in /secrets/${SCEWL_ID}/sed.csr -CA /secrets/sss/ca.crt -CAkey /secrets/sss/ca.key -CAcreateserial -out /secrets/${SCEWL_ID}/sed.crt -extfile /secrets/configs/sed_ext.cfg


# Create C file for this SED that contains the CA, cert, key, and seed

# CA
RUN python3 -c \
"\
import os; \
import sys; \
fp = open(sys.argv[1], 'r'); \
s = ''.join('\"' + line.rstrip() + '\\\r\\\n\" \\\' + '\n' for line in fp.readlines()); \
s = s[0:len(s)-3] + ';'; \
s = 'const char provision_ca[] = ' + s; \
print(s) \
" /secrets/sss/ca.crt > /secrets/${SCEWL_ID}/sed_secrets.c
RUN echo "" >> /secrets/${SCEWL_ID}/sed_secrets.c

# Cert
RUN python3 -c \
"\
import os; \
import sys; \
fp = open(sys.argv[1], 'r'); \
s = ''.join('\"' + line.rstrip() + '\\\r\\\n\" \\\' + '\n' for line in fp.readlines()); \
s = s[0:len(s)-3] + ';'; \
s = 'const char sed_provision_crt[] = ' + s; \
print(s) \
" /secrets/${SCEWL_ID}/sed.crt >> /secrets/${SCEWL_ID}/sed_secrets.c
RUN echo "" >> /secrets/${SCEWL_ID}/sed_secrets.c

# Key
RUN python3 -c \
"\
import os; \
import sys; \
fp = open(sys.argv[1], 'r'); \
s = ''.join('\"' + line.rstrip() + '\\\r\\\n\" \\\' + '\n' for line in fp.readlines()); \
s = s[0:len(s)-3] + ';'; \
s = 'const char sed_provision_key[] = ' + s; \
print(s) \
" /secrets/${SCEWL_ID}/sed.key >> /secrets/${SCEWL_ID}/sed_secrets.c
RUN echo "" >> /secrets/${SCEWL_ID}/sed_secrets.c


# Create seed pool for SED
ARG RAND_BYTES=96

# Generate seed and add to file
RUN python3 -c \
"\
import os; \
import sys; \
rands = os.urandom(int(sys.argv[1])).hex(); \
a = list(map(''.join, zip(*[iter(rands)]*2))); \
array = ''.join(map(lambda i: '0x' + i + ',', a)); \
array = '{' + array + '}'; \
array = array[0:len(array)-2]; \
array = array + '}'; \
array = 'const unsigned char seed_pool[] = ' + array + ';'; \
print(array) \
" $RAND_BYTES >> /secrets/${SCEWL_ID}/sed_secrets.c


# Create C header file so multiple files can access the values in flash

# Guards
RUN echo "#ifndef SED_SECRETS_H" > /secrets/${SCEWL_ID}/sed_secrets.h
RUN echo "#define SED_SECRETS_H" >> /secrets/${SCEWL_ID}/sed_secrets.h
RUN echo "" >> /secrets/${SCEWL_ID}/sed_secrets.h

# Define pool size
RUN echo "#define SEED_POOL_SIZE $RAND_BYTES" >> /secrets/${SCEWL_ID}/sed_secrets.h
RUN echo "" >> /secrets/${SCEWL_ID}/sed_secrets.h

# Global references
RUN echo "extern const char provision_ca[];" >> /secrets/${SCEWL_ID}/sed_secrets.h
RUN echo "extern const char sed_provision_crt[];" >> /secrets/${SCEWL_ID}/sed_secrets.h
RUN echo "extern const char sed_provision_key[];" >> /secrets/${SCEWL_ID}/sed_secrets.h
RUN echo "extern const unsigned char seed_pool[];" >> /secrets/${SCEWL_ID}/sed_secrets.h
RUN echo "" >> /secrets/${SCEWL_ID}/sed_secrets.h

# End guard
RUN echo "#endif // SED_SECRETS_H" >> /secrets/${SCEWL_ID}/sed_secrets.h