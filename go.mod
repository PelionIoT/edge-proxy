module github.com/PelionIoT/edge-proxy

go 1.16

replace (
	github.com/gorilla/websocket v1.4.2 => github.com/pelioniot/websocket v1.4.2-1
	golang.org/x/net => golang.org/x/net v0.0.0-20210520170846-37e1c6afe023 // Required to fix CVE-2021-33194
)

require (
	github.com/PelionIoT/remotedialer v1.0.3
	github.com/elazarl/goproxy v0.0.0-20210110162100-a92cc753f88e
	github.com/elazarl/goproxy/ext v0.0.0-20190711103511-473e67f1d7d2
	github.com/gorilla/websocket v1.4.2
	github.com/onsi/ginkgo v1.12.3
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
)
