FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
WORKDIR /src/operator
COPY operator/go.mod operator/go.sum* ./
COPY pkg/actioncatalog/go.mod /src/pkg/actioncatalog/go.mod
RUN go mod download
COPY operator/ ./
COPY pkg/actioncatalog/ /src/pkg/actioncatalog/
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/kubeathrix-operator ./cmd/manager

FROM gcr.io/distroless/static-debian12:nonroot@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f
ARG VERSION=0.2.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="KubeAthrix Operator" \
      org.opencontainers.image.description="Typed Kubernetes remediation controller" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source="https://github.com/atharvaai/KubeAthrix" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/kubeathrix-operator /manager
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/manager"]
