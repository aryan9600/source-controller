FROM ghcr.io/fluxcd/golang-with-libgit2 as build

FROM gcr.io/oss-fuzz-base/base-builder-go

RUN apt-get update && apt-get install -y cmake openssl libssh2-1-dev pkg-config

COPY ./ $GOPATH/src/github.com/fluxcd/source-controller/
COPY ./tests/fuzz/oss_fuzz_build.sh $SRC/build.sh

ARG LIBGIT2_PATH=$GOPATH/src/github.com/fluxcd/source-controller/build/libgit2/libgit2-1.1.1-4
ARG INSTALLED_DIR=/usr/local/x86_64-alpine-linux-musl
RUN mkdir -p $GOPATH/src/github.com/fluxcd/source-controller/build
COPY --from=build $INSTALLED_DIR $LIBGIT2_PATH
RUN find $LIBGIT2_PATH -type f -name "*.pc" | xargs -I {} sed -i "s;$INSTALLED_DIR;$LIBGIT2_PATH;g" {}

WORKDIR $SRC
