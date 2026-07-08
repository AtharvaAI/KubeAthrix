FROM golang:1.25-alpine AS build
WORKDIR /src
COPY operator/go.mod operator/go.sum* ./
RUN go mod download
COPY operator/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/kubeathrix-operator ./cmd/manager

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kubeathrix-operator /manager
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/manager"]
