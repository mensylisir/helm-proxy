# Build Stage
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# 设置代理加速编译
ENV GOPROXY=https://goproxy.cn,direct
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -a -installsuffix cgo -o helm-proxy .

# Runtime Stage
FROM alpine:3.17

# 安装基础工具和 git (helm 插件可能需要)
RUN apk --no-cache add ca-certificates git curl bash

# 安装 Helm 命令行工具（辅助 SDK 进行某些仓库操作）
RUN curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 && \
    chmod 700 get_helm.sh && \
    ./get_helm.sh

WORKDIR /root/
COPY --from=builder /app/helm-proxy .

# 创建必要的缓存目录
RUN mkdir -p /root/.cache/helm /root/.config/helm

# 环境变量
ENV HELM_DRIVER=secret
ENV GIN_MODE=release
ENV PORT=8443

EXPOSE 8443
CMD ["./helm-proxy"]