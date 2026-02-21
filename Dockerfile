FROM golang:1.22-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /out/incomudon-pwa-client .

FROM alpine:3.20
RUN apk add --no-cache libgcc opus && adduser -D -H -s /sbin/nologin app
COPY --from=build /out/incomudon-pwa-client /usr/local/bin/incomudon-pwa-client
COPY third_party/libcodec2 /opt/libcodec2
COPY third_party/libopus /opt/libopus
USER app
EXPOSE 8080/tcp
ENTRYPOINT ["/usr/local/bin/incomudon-pwa-client"]
