FROM golang:1.22 AS build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/sshmux

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /go/bin/sshmux /
CMD ["/sshmux"]
