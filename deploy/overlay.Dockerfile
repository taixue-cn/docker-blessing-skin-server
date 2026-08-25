# Offline production overlay for configuration-only releases. The base image
# is supplied by immutable local image ID so Docker never resolves a registry.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root
COPY config/nginx.conf /etc/nginx/nginx.conf
USER nobody
