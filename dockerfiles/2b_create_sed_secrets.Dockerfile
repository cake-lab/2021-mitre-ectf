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


# Create C file and C header for this SED that contains the CA, cert, key, and seed
RUN python3 /secrets/configs/gen_secrets.py /secrets/sss /secrets/${SCEWL_ID}