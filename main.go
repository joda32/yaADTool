package main

import (
	"flag"
)

func parseOptions() *xxx {
	upn := flag.String("u", "", "Username (username@domain)")
	password := flag.String("p", "", "Password")
	ntlm := flag.String("H", "", "Use NTLM authentication")
	dc := flag.String("dc", "", "IP address or FQDN of target DC")
	scheme := flag.Bool("s", false, "Bind using LDAPS")
	logFile := flag.String("o", "", "Log file")
	socks4 := flag.String("socks4", "", "SOCKS4 Proxy Address (ip:port)")
	socks4a := flag.String("socks4a", "", "SOCKS4A Proxy Address (ip:port)")
	socks5 := flag.String("socks5", "", "SOCKS5 Proxy Address (ip:port)")
	help := flag.Bool("h", false, "Display help menu")

	flag.Parse()
	return &xxx{
		upn:      *upn,
		password: *password,
		ntlm:     *ntlm,
		dc:       *dc,
		scheme:   *scheme,
		logFile:  *logFile,
		socks4:   *socks4,
		socks4a:  *socks4a,
		socks5:   *socks5,
		help:     *help}

}

func main() {
	dc := flag.String("dc", "", "Domain controller we are targeting")
	// user
	// password
	// domain
	// action
	// output_type
	// output_location
	// socks
	// proxy_host
	// proxy_port
	//
}
