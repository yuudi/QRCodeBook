FROM golang:1.24-alpine as builder

WORKDIR /go/src

# Optimize the build cache
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o "dist/main" .

FROM alpine:latest as runner

WORKDIR /app

COPY --from=builder /go/src/dist/main .

CMD ["./main"]
