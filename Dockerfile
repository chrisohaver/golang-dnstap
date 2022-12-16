# build
FROM golang:1.19-alpine AS build
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o dnstap-relay ./dnstap

# deploy
FROM alpine:3.17
WORKDIR /
COPY --from=build /app/dnstap-relay ./
ENTRYPOINT ["/dnstap-relay"]
