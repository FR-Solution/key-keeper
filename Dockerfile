FROM golang:1.19.1-alpine3.16 as builder

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

ARG VERSION
ARG PROJECT

RUN go install -ldflags "-s \
    -X main.Version=${VERSION}" \
    /app/cmd/${PROJECT}

FROM alpine:3.16.0

ARG PROJECT

COPY --from=builder /go/bin/${PROJECT} /usr/local/bin/app

ENTRYPOINT ["app"]