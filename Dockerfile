FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# Builder tools never enter the boot image.
RUN apk add --no-cache coreutils cpio findutils gzip kmod python3 shellcheck ukify
WORKDIR /src
ENTRYPOINT ["/bin/sh"]
