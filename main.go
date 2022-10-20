package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/go-ldap/ldap/v3"

	actions "github.com/joda32/yaADTool/actions"
	gvars "github.com/joda32/yaADTool/common"
)

func parseOptions() *gvars.Config {
	upn := flag.String("u", "", "Username (username@domain)")
	password := flag.String("p", "", "Password")
	ntlm := flag.String("H", "", "Use NTLM authentication")
	dc := flag.String("dc", "", "IP address or FQDN of target DC")
	scheme := flag.Bool("s", false, "Bind using LDAPS")
	outFile := flag.String("o", "", "Output file")
	outFormat := flag.String("f", "", "Output format CSV/JSON")
	socks4 := flag.Bool("socks4", false, "SOCKS4 Proxy Address (ip:port)")
	socks4a := flag.Bool("socks4a", false, "SOCKS4A Proxy Address (ip:port)")
	socks5 := flag.Bool("socks5", false, "SOCKS5 Proxy Address (ip:port)")
	action := flag.String("a", "", "Action to perform")
	help := flag.Bool("h", false, "Display help menu")
	query := flag.String("q", "", "Custom query to run")

	flag.Parse()
	return &gvars.Config{
		Upn:       *upn,
		Password:  *password,
		Ntlm:      *ntlm,
		Dc:        *dc,
		Scheme:    *scheme,
		OutFormat: *outFormat,
		LogFile:   "",
		OutFile:   *outFile,
		Socks4:    *socks4,
		Socks4a:   *socks4a,
		Socks5:    *socks5,
		Action:    *action,
		Help:      *help,
		Query:     *query,
	}

}

func processOutput() {

}

func main() {
	config := parseOptions()

	var conn *ldap.Conn
	var err error

	log.Println("Connecting.")
	// TODO: Wrap connection into a function with scheme and proxy support
	conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", config.Dc, 389))

	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	log.Println("Connected.")
	log.Println("Authenticating.")
	// TODO: Wrap bind into a function add support for kerberos and pth support
	if config.Password != "" {
		err = conn.Bind(config.Upn, config.Password)
		if err != nil {
			log.Fatal(err)
		} else {
			log.Println("Authenticated.")
		}
	}

	log.Println("Retrieving baseDN.")
	actions.QueryBaseDN = actions.GetbaseDN(conn)
	log.Printf("Using BaseDN [%s]\n", actions.QueryBaseDN)

	// TODO: Need to be smarter with this, but lets start small and add in what is needed
	switch config.Action {
	case "full":
		actions.PerformFullDump()
	case "policy":
		actions.GetPasswordPolicy(conn)
	case "custom":
		result := actions.ExecuteCustomLdapQuery(conn, config.Query)
		j, err := json.Marshal(result)

		fmt.Println(string(j), err)
	default:
		log.Println("Todo: print all options")
	}

}
