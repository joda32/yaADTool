package actions

import (
	"fmt"
	"log"

	"github.com/bwmarrin/go-objectsid"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

func CreateSearchReq(baseDN string, query string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, 0, 0, 0, false,
		query,
		[]string{},
		nil,
	)
}

func PerformFullDump() {
	log.Println("Todo: perform full dump here")
}

func GetAllUsers() {
	log.Println("Todo: dump all users")
}

func GetAllGroups() {
	log.Println("Todo: dump all groups")
}

func GetAllComputers() {
	log.Println("Todo: dump all computers")
}

// Todo: lots and lots of clean up here, also move result output to a struct and consume/process by the currently non-existing results processor
func GetPasswordPolicy(conn *ldap.Conn) {
	log.Println("Retrieving password policies")
	req := CreateSearchReq(QueryBaseDN, QueryPasswordPolicy)

	result, err := conn.Search(req)
	if err != nil {
		log.Printf("Query error, %s\n", err)
	}
	log.Printf("Returned [%d] policies", len(result.Entries))
	if len(result.Entries) > 0 {
		for domainDNSResult := range result.Entries {
			for _, element := range result.Entries[domainDNSResult].Attributes {
				fmt.Println("Key:", result.Entries[domainDNSResult].GetAttributeValue(element.Name), "=>", "Element:", element.Name)
			}
			minPwdLength := result.Entries[domainDNSResult].GetAttributeValue("minPwdLength")
			pwdHistoryLength := result.Entries[domainDNSResult].GetAttributeValue("pwdHistoryLength")
			maxPwdAge := result.Entries[domainDNSResult].GetAttributeValue("maxPwdAge")
			minPwdAge := result.Entries[domainDNSResult].GetAttributeValue("minPwdAge")
			lockoutThreshold := result.Entries[domainDNSResult].GetAttributeValue("lockoutThreshold")
			lockoutDuration := result.Entries[domainDNSResult].GetAttributeValue("lockoutDuration")
			lockOutObservationWindow := result.Entries[domainDNSResult].GetAttributeValue("lockOutObservationWindow")
			//pwdProperties := result.Entries[domainDNSResult].GetAttributeValue("pwdProperties")
			log.Printf("Min password len: %s\n", minPwdLength)
			log.Printf("Min password history: %s\n", pwdHistoryLength)

			log.Printf("Minimum Password Length: %s\n", minPwdLength)
			log.Printf("Password History Length: %s\n", pwdHistoryLength)
			log.Printf("Lockout count: %s\n", lockoutThreshold)

			//check if lockout duration is 0 (until admin unlock )
			if lockoutDuration == "-9223372036854775808" {
				log.Printf("Lockout Duration: Until Admin Unlock\n")
			} else {
				log.Printf("Lockout Duration: %.0f minutes\n", ConvertToMinutes(lockoutDuration))
			}

			//check if min password age is None
			log.Printf("Reset Account Lockout Counter: %.0f minutes\n", ConvertToMinutes(lockOutObservationWindow))
			if minPwdAge == "0" {
				log.Printf("Minimum Password Age: None\n")
			} else {
				log.Printf("Minimum Password Age: %.0f day(s)\n", ConvertToMinutes(minPwdAge)/60/24)
			}

			log.Printf("Maximum Password Age: %.0f day(s)\n", ConvertToMinutes(maxPwdAge)/60/24)
			//log.Printf("\t\nPassword Complexity: \t%s", pwdPropertiesResolved)
		}
	}
}

func ExecuteCustomLdapQuery(conn *ldap.Conn, query string) []map[string]string {
	var err error
	log.Println("Executing custom LDAP query")
	req := CreateSearchReq(QueryBaseDN, query)
	var result []map[string]string

	queryresult, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		log.Printf("Query error, %s\n", err)
		return nil
	}
	log.Printf("Returned [%d] entries", len(queryresult.Entries))
	if len(queryresult.Entries) > 0 {
		for i := range queryresult.Entries {
			e := make(map[string]string)
			for _, element := range queryresult.Entries[i].Attributes {
				// Todo: Probably want to refactor this into a helper function to deal with output
				buff := ""
				switch element.Name {
				case "objectSid":
					buff = objectsid.Decode(queryresult.Entries[i].GetRawAttributeValue(element.Name)).String()
				case "objectGUID":
					var guid uuid.UUID
					guid, err = uuid.Parse(fmt.Sprintf("%x", queryresult.Entries[i].GetRawAttributeValue(element.Name)))
					if err == nil {
						buff = guid.String()
					} else {
						fmt.Println(err)
					}
				case "msDS-GenerationId":
					buff = fmt.Sprintf("%x", queryresult.Entries[i].GetRawAttributeValue(element.Name))
				default:
					buff = queryresult.Entries[i].GetAttributeValue(element.Name)
				}
				//fmt.Print(element.Name, "=", buff, ", ")
				e[element.Name] = buff
			}
			//fmt.Print("\n")
			result = append(result, e)
		}
	}
	//fmt.Print(result)
	return result
}
