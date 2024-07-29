module github.com/USTC-vlab/sshmux

go 1.21

require golang.org/x/crypto v0.24.0
require github.com/pires/go-proxyproto v0.7.0

require golang.org/x/sys v0.21.0 // indirect

replace golang.org/x/crypto => ./crypto
