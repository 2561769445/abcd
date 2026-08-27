# 构建前端 → 编译主控 → 运行镜像
FROM node:20-alpine AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --registry=https://registry.npmmirror.com || npm install --registry=https://registry.npmmirror.com
COPY frontend/ .
RUN npm run build

FROM golang:1.26-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN rm -rf master/dist && cp -r /fe/dist master/dist
RUN go build -ldflags="-s -w" -trimpath -o /abcd-master .

FROM alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata && adduser -D abcd
COPY --from=build /abcd-master /app/abcd-master
USER abcd
EXPOSE 8080
ENTRYPOINT ["/app/abcd-master", "-master"]
