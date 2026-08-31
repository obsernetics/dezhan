# dezhan operator image. Standard Go multi-stage build on distroless static.
FROM golang:1.27 AS build
WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux go build -a -o manager ./cmd

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /workspace/manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
