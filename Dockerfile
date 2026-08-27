FROM --platform=$BUILDPLATFORM golang:1.27 AS build

WORKDIR /go/src/app
COPY . .

RUN go mod download

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /go/bin/sshmux -ldflags='-s -w' -trimpath

FROM gcr.io/distroless/static-debian13:nonroot
COPY ./etc/config.example.toml /etc/config.example.toml 
COPY --from=build /go/bin/sshmux /
CMD ["/sshmux"]
