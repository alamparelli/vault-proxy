FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /vault-server ./cmd/vault-server
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /vault-cli ./cmd/vault-cli

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /vault-server /usr/local/bin/vault-server
COPY --from=builder /vault-cli /usr/local/bin/vault-cli

RUN adduser -D -u 1000 vault \
 && mkdir -p /data \
 && chown vault:vault /data

USER vault

VOLUME /data
EXPOSE 8390

ENTRYPOINT ["vault-server"]
CMD ["--listen", "0.0.0.0:8390", "--data-dir", "/data"]
