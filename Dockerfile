FROM golang:1-alpine AS build

RUN apk add --no-cache git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go install ./cmd/passidp

FROM debian:trixie

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates procps

COPY --from=build /go/bin/passidp /usr/bin/

CMD ["/usr/bin/passidp"]
