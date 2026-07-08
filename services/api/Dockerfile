FROM golang:1.25-alpine AS build
WORKDIR /src
COPY services/api/go.mod services/api/go.sum* ./
RUN go mod download
COPY services/api/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/kubeathrix-api ./cmd/kubeathrix-api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kubeathrix-api /kubeathrix-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/kubeathrix-api"]
