#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;
ADD . /opt/workspace/trustbloc-did-method
WORKDIR /opt/workspace/trustbloc-did-method
ENV EXECUTABLES go git

FROM golang as trustbloc-did-method
RUN make did-method-rest


FROM alpine:${ALPINE_VER} as base
LABEL org.opencontainers.image.source https://github.com/trustbloc/trustbloc-did-method

COPY --from=trustbloc-did-method /opt/workspace/trustbloc-did-method/.build/bin/did-method /usr/local/bin
WORKDIR /usr/local/bin
ENTRYPOINT ["did-method"]
