module github.com/PelionIoT/edge-proxy

go 1.18

replace (
	github.com/gorilla/websocket v1.4.2 => github.com/pelioniot/websocket v1.4.2-1
	golang.org/x/net => golang.org/x/net v0.0.0-20210520170846-37e1c6afe023 // Required to fix CVE-2021-33194
)

require (
	github.com/PelionIoT/remotedialer v1.0.4
	github.com/elazarl/goproxy v0.0.0-20210110162100-a92cc753f88e
	github.com/elazarl/goproxy/ext v0.0.0-20190711103511-473e67f1d7d2
	github.com/gorilla/websocket v1.4.2
	github.com/onsi/ginkgo v1.12.3
	github.com/onsi/gomega v1.10.1
)

require (
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/nxadm/tail v1.4.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	golang.org/x/net v0.0.0-20200520004742-59133d7f0dd7 // indirect
	golang.org/x/sys v0.0.0-20210423082822-04245dca01da // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.3.0 // indirect
)
