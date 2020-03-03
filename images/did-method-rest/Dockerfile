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
ADD . /opt/workspace/bloc-did-method
WORKDIR /opt/workspace/bloc-did-method
ENV EXECUTABLES go git

FROM golang as bloc-did-method
RUN make did-method-rest


FROM alpine:${ALPINE_VER} as base
COPY --from=bloc-did-method /opt/workspace/bloc-did-method/.build/bin /usr/local/bin
WORKDIR /usr/local/bin
ENTRYPOINT ["did-method-rest"]
