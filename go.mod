module github.com/PelionIoT/edge-proxy

go 1.20

replace github.com/gorilla/websocket v1.5.1 => github.com/pelioniot/websocket v1.5.1-3

require (
	github.com/PelionIoT/remotedialer v1.0.4
	github.com/elazarl/goproxy v1.7.0
	github.com/elazarl/goproxy/ext v0.0.0-20250205090437-1f65b1b95ba5
	github.com/gorilla/websocket v1.5.1
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.26.0
)

require (
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
