FROM golang:1.22.1-alpine AS builder

RUN apk add --no-cache gcc musl-dev

ENV APP_HOME /app
ENV CGO_ENABLED 1

WORKDIR $APP_HOME

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main ./cmd

# Начинаем новый этап с нуля (multi-stage build)
FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/main .
COPY ./docs ./docs

EXPOSE 8081
