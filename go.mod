module github.com/PelionIoT/edge-proxy

go 1.12

require (
	github.com/PelionIoT/remotedialer v1.0.0
	github.com/gorilla/websocket v1.4.2
	github.com/onsi/ginkgo v1.12.3
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9 // indirect
)

replace github.com/gorilla/websocket v1.4.2 => github.com/pelioniot/websocket v1.4.2-1
