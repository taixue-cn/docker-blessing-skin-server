#!/usr/bin/env sh
apk --no-cache add curl
curl --silent --show-error --fail \
  --retry 15 --retry-connrefused --retry-delay 1 \
  http://app:8080 | grep 'PHP 8.1'

# Application-owned RFC 8615 routes must not be blocked as dot files.
curl --silent --show-error --fail \
  http://app:8080/.well-known/change-password | grep 'PHP 8.1'
