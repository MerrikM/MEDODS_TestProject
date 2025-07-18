FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o app ./cmd/main.go

# Финальный образ
FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/app .
COPY config.yaml ../

RUN apk add --no-cache ca-certificates

EXPOSE 8090
CMD ["./app"]