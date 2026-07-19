FROM golang:1.25.12-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build
WORKDIR /src/operator
COPY operator/go.mod operator/go.sum* ./
COPY pkg/actioncatalog/go.mod /src/pkg/actioncatalog/go.mod
RUN go mod download
COPY operator/ ./
COPY pkg/actioncatalog/ /src/pkg/actioncatalog/
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/kubeathrix-operator ./cmd/manager

FROM gcr.io/distroless/static-debian12:nonroot@sha256:aef9602f8710ec12bde19d593fed1f76c708531bb7aba205110f1029786ead7b
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
