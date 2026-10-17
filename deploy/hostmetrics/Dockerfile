FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/hostmetrics ./cmd/hostmetrics
COPY internal/monitoring ./internal/monitoring
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/hostmetrics ./cmd/hostmetrics

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN addgroup -S -g 65532 app && adduser -S -D -H -u 65532 -G app app
COPY --from=build /out/hostmetrics /usr/local/bin/hostmetrics
USER 65532:65532
EXPOSE 8181
ENTRYPOINT ["/usr/local/bin/hostmetrics"]
