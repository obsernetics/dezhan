# dezhan CSI driver image. The node plugin shells out to mountpoint-s3
# (mount-s3), so the runtime image bundles it plus FUSE.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 GOOS=linux go build -o /dezhan-csi ./cmd

FROM debian:13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates fuse3 wget \
 && wget -q https://s3.amazonaws.com/mountpoint-s3-release/latest/x86_64/mount-s3.deb -O /tmp/mount-s3.deb \
 && apt-get install -y --no-install-recommends /tmp/mount-s3.deb \
 && rm -f /tmp/mount-s3.deb \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /dezhan-csi /usr/local/bin/dezhan-csi
ENTRYPOINT ["/usr/local/bin/dezhan-csi"]
