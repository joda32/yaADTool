package gvars

type Config struct {
	Upn       string
	Password  string
	Ntlm      string
	Dc        string
	Scheme    bool
	OutFormat string
	OutFile   string
	LogFile   string
	Socks4    bool
	Socks4a   bool
	Socks5    bool
	Action    string
	Help      bool
}
