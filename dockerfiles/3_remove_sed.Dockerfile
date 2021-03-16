# 2021 Collegiate eCTF
# Remove SED Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

# load current SSS container to modify
# NOTE: only sss/ and its subdirectories in the repo are accessible to this Dockerfile as .
ARG DEPLOYMENT
FROM ${DEPLOYMENT}/sss

ARG SCEWL_ID

# do whatever you need to remove the SED from the deployment

# Delete all certificate files for the SED
RUN rm -rf /secrets/${SCEWL_ID}