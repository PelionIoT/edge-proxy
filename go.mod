module github.com/PelionIoT/edge-proxy

go 1.18

replace github.com/gorilla/websocket v1.4.2 => github.com/pelioniot/websocket v1.4.2-1

require (
	github.com/PelionIoT/remotedialer v1.0.4
	github.com/elazarl/goproxy v0.0.0-20210110162100-a92cc753f88e
	github.com/elazarl/goproxy/ext v0.0.0-20190711103511-473e67f1d7d2
	github.com/gorilla/websocket v1.4.2
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.26.0
)

require (
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
