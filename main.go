package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"src.agwa.name/go-listener"
)

func main() {
	var (
		listenArgs       []string
		proxy            bool
		backendArg       string
		ipv6SourcePrefix net.IP
		allowed          []*net.IPNet
		defaultHostname  string
	)

	flag.Func("listen", "Socket to listen on (repeatable)", func(arg string) error {
		listenArgs = append(listenArgs, arg)
		return nil
	})
	flag.BoolVar(&proxy, "proxy", false, "Use PROXY protocol when talking to backend")
	flag.StringVar(&backendArg, "backend", "", ":PORT or /path/to/socket/dir for backends")
	flag.Func("ipv6-source-prefix", "IPv6 source prefix for embedding client IPv4 address", func(arg string) error {
		ipv6SourcePrefix = net.ParseIP(arg)
		if ipv6SourcePrefix == nil {
			return fmt.Errorf("not a valid IP address")
		}
		if ipv6SourcePrefix.To4() != nil {
			return fmt.Errorf("not an IPv6 address")
		}
		return nil
	})
	flag.Func("allow", "CIDR of allowed backends (repeatable)", func(arg string) error {
		_, ipnet, err := net.ParseCIDR(arg)
		if err != nil {
			return err
		}
		allowed = append(allowed, ipnet)
		return nil
	})
	flag.StringVar(&defaultHostname, "default-hostname", "", "Default hostname if client does not provide SNI")
	flag.Parse()

	server := &Server{
		ProxyProtocol:   proxy,
		DefaultHostname: defaultHostname,
	}

	if strings.HasPrefix(backendArg, "/") {
		server.Backend = &UnixDialer{Directory: backendArg}
	} else if strings.HasPrefix(backendArg, ":") {
		port := strings.TrimPrefix(backendArg, ":")
		if len(allowed) == 0 {
			log.Fatal("At least one -allow flag must be specified when you use TCP backends")
		}
		server.Backend = &TCPDialer{Port: port, Allowed: allowed, IPv6SourcePrefix: ipv6SourcePrefix}
	} else {
		log.Fatal("-backend must be a TCP port number (e.g. :443) or a path to a socket directory")
	}

	if len(listenArgs) == 0 {
		log.Fatal("At least one -listen flag must be specified")
	}

	listeners, err := listener.OpenAll(listenArgs)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.CloseAll(listeners)

	for _, l := range listeners {
		go serve(l, server)
	}

	select {}
}

func serve(listener net.Listener, server *Server) {
	log.Fatal(server.Serve(listener))
}
