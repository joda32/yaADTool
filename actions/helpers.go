package actions

import (
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func GetbaseDN(conn *ldap.Conn) string {

	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) > 0 {
		return sr.Entries[0].GetAttributeValue("defaultNamingContext")
	} else {
		log.Fatal("Failed getting baseDN, can't continue.")
	}
	return ""
}

func ConvertLDAPTime(t int) time.Time {
	LDAPtime := t
	winSecs := LDAPtime / 10000000
	timeStamp := winSecs - 11644473600
	return time.Unix(int64(timeStamp), 0)
}

func ConvertToMinutes(t string) (minutes float64) {
	removeMinus := strings.Trim(t, "-")
	first5 := removeMinus[:5]
	trailing := removeMinus[5:]
	number, _ := strconv.ParseFloat(first5, 64)
	decimal := float64(number / 10000)
	seconds := (decimal * (math.Pow(10, float64(len(trailing))) / 1000))
	minutes = seconds / 60

	return
}
