# stage: build ---------------------------------------------------------

FROM golang:1.22-alpine as build

RUN apk add --no-cache gcc musl-dev linux-headers

WORKDIR /go/src/github.com/flashbots/vault-auth-plugin-attest

COPY go.* ./
RUN go mod download

COPY . .

RUN go build -o bin/vault-auth-plugin-attest -ldflags "-s -w" github.com/flashbots/vault-auth-plugin-attest/cmd

# stage: run -----------------------------------------------------------

FROM alpine

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=build /go/src/github.com/flashbots/vault-auth-plugin-attest/bin/vault-auth-plugin-attest ./vault-auth-plugin-attest

ENTRYPOINT ["/app/vault-auth-plugin-attest"]
