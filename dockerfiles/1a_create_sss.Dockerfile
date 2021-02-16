# 2021 Collegiate eCTF
# SSS Creation Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

FROM ubuntu:focal

# Add environment customizations here
# NOTE: do this first so Docker can used cached containers to skip reinstalling everything
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y python3 && \
    apt-get install -y openssl

# add any deployment-wide secrets here
RUN mkdir /secrets
RUN mkdir /secrets/sss
RUN mkdir /secrets/configs

# map in SSS
# NOTE: only sss/ and its subdirectories in the repo are accessible to this Dockerfile as .
# NOTE: you can do whatever you need here to create the sss program, but it must end up at /sss
# NOTE: to maximize the useage of container cache, map in only the files/directories you need
#       (e.g. only mapping in the files you need for the SSS rather than the entire repo)
ADD sss.py /sss

# Add certificate configurations
ADD ca_crt.cfg /secrets/configs/ca_crt.cfg
ADD sed_crt.cfg /secrets/configs/sed_crt.cfg
ADD sed_ext.cfg /secrets/configs/sed_ext.cfg

# Create key and cert for SSS certificate authority (CA)
RUN openssl genrsa -out /secrets/sss/ca.key 2048
RUN openssl req -x509 -new -nodes -key /secrets/sss/ca.key -out /secrets/sss/ca.crt -config /secrets/configs/ca_crt.cfg