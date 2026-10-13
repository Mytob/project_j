FROM golang:1.25.2-alpine3.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/admin ./cmd/admin
COPY internal/auth ./internal/auth
COPY internal/totp ./internal/totp
COPY internal/admin ./internal/admin
COPY internal/whitelist ./internal/whitelist
COPY internal/wireguard ./internal/wireguard
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/admin ./cmd/admin

FROM alpine:3.22
RUN addgroup -S -g 65532 app && adduser -S -D -H -u 65532 -G app app
COPY --from=build /out/admin /usr/local/bin/admin
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/admin"]
