FROM golang:1.25.12-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build
WORKDIR /src/services/api
COPY services/api/go.mod services/api/go.sum* ./
COPY pkg/actioncatalog/go.mod /src/pkg/actioncatalog/go.mod
RUN go mod download
COPY services/api/ ./
COPY pkg/actioncatalog/ /src/pkg/actioncatalog/
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/kubeathrix-api ./cmd/kubeathrix-api

FROM gcr.io/distroless/static-debian12:nonroot@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f
ARG VERSION=0.2.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="KubeAthrix API" \
      org.opencontainers.image.description="Authenticated Kubernetes guardrail API" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source="https://github.com/atharvaai/KubeAthrix" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/kubeathrix-api /kubeathrix-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/kubeathrix-api"]
