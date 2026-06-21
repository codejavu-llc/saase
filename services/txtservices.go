package services

import (
	"context"
	"net"
	"strings"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func CheckTXTServices(domain string) []string {
	var foundServices []string

	txtRecords, err := net.DefaultResolver.LookupTXT(context.Background(), domain)
	if err != nil {
		return foundServices
	}

	caser := cases.Title(language.English)

	for _, record := range txtRecords {
		lowerRecord := strings.ToLower(record)
		
		// 1. Check for verification tokens formatted with '=' or '-' or '_'
		if strings.Contains(lowerRecord, "verification") || strings.Contains(lowerRecord, "verify") {
			parts := strings.FieldsFunc(record, func(r rune) bool {
				return r == '=' || r == ' ' || r == '-' || r == '_' || r == ':'
			})

			if len(parts) > 0 {
				candidate := parts[0]
				lowerCandidate := strings.ToLower(candidate)
				
				// Exclude generic structures and SPF records
				if lowerCandidate == "v" || lowerCandidate == "spf1" || lowerCandidate == "descriptive" || lowerCandidate == "text" {
					continue
				}

				formattedName := caser.String(lowerCandidate)
				if formattedName != "" {
					foundServices = append(foundServices, formattedName)
				}
			}
		}
	}

	return foundServices
}
