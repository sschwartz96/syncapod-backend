FROM golang:alpine
RUN mkdir /app
COPY . /app
WORKDIR /app
RUN go build -o /app/main cmd/main.go

FROM alpine:latest AS prod
# RUN apk --no-cache add ca-certificates
WORKDIR /syncapod
COPY --from=0 /app/main /syncapod
COPY ./config.json /syncapod
CMD ["/syncapod/main"]
