FROM golang:1.19.1-alpine3.16 as builder

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

ARG VERSION

RUN go install -ldflags "-s \
    -X main.Version=${VERSION}" \
    /app/cmd/key-keeper

FROM alpine:3.15.0

COPY --from=builder /go/bin/key-keeper /usr/local/bin/key-keeper

ENTRYPOINT ["/usr/local/bin/key-keeper"]