FROM node:26.5.0-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS build
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/console apps/console
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @kubeathrix/console build

FROM nginxinc/nginx-unprivileged:1.31.2-alpine3.23@sha256:592b23aa79a6e6c08ba4b20f1fff700e1328895705966722608e115d62e52d39
ARG VERSION=0.2.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="KubeAthrix Console" \
      org.opencontainers.image.description="OIDC-enabled Kubernetes guardrail operator console" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source="https://github.com/atharvaai/KubeAthrix" \
      org.opencontainers.image.licenses="Apache-2.0"
USER root
RUN apk del --no-cache curl
USER 101
COPY --from=build /src/apps/console/dist /usr/share/nginx/html
COPY apps/console/nginx.conf.template /etc/nginx/templates/default.conf.template
ENV KUBEATHRIX_API_UPSTREAM=http://kubeathrix-api:8080
EXPOSE 8080
