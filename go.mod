module github.com/USTC-vlab/sshmux

go 1.23.0

toolchain go1.24.2

require golang.org/x/crypto v0.37.0

require github.com/libp2p/go-reuseport v0.4.0

require github.com/pires/go-proxyproto v0.7.0

require github.com/pelletier/go-toml/v2 v2.2.2

require github.com/fsnotify/fsnotify v1.7.0

require github.com/julienschmidt/httprouter v1.3.0

require golang.org/x/sys v0.32.0 // indirect

replace golang.org/x/crypto => ./crypto
