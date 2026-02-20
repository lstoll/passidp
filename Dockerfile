FROM golang:1-trixie AS build

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
