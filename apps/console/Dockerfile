FROM node:24.7.0-alpine@sha256:be4d5e92ac68483ec71440bf5934865b4b7fcb93588f17a24d411d15f0204e4f AS build
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/console apps/console
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @kubeathrix/console build

FROM nginxinc/nginx-unprivileged:1.31.2-alpine3.23@sha256:6320020c7da8714feab524e02c08c5a1958675c4e68700e93a2fd8970b065786
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
