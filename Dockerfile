FROM golang:1.23 AS build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/sshmux -trimpath

FROM gcr.io/distroless/static-debian12:nonroot
COPY ./etc/config.example.toml /etc/config.example.toml 
COPY --from=build /go/bin/sshmux /
CMD ["/sshmux"]
