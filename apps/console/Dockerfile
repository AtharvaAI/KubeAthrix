FROM node:24-alpine AS build
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-workspace.yaml ./
COPY apps/console/package.json apps/console/package.json
RUN pnpm install --filter @kubeathrix/console --frozen-lockfile=false
COPY apps/console apps/console
RUN pnpm --filter @kubeathrix/console build

FROM nginx:1.27-alpine
COPY --from=build /src/apps/console/dist /usr/share/nginx/html
EXPOSE 80
