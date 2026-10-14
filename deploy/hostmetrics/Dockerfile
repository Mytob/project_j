FROM golang:1.25.2-alpine3.22@sha256:06cdd34bd531b810650e47762c01e025eb9b1c7eadd191553b91c9f2d549fae8 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/hostmetrics ./cmd/hostmetrics
COPY internal/monitoring ./internal/monitoring
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/hostmetrics ./cmd/hostmetrics

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN addgroup -S -g 65532 app && adduser -S -D -H -u 65532 -G app app
COPY --from=build /out/hostmetrics /usr/local/bin/hostmetrics
USER 65532:65532
EXPOSE 8181
ENTRYPOINT ["/usr/local/bin/hostmetrics"]
