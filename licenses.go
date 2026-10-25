// Package ssjack provides distribution notices for the ssjack executable.
package ssjack

import _ "embed"

//go:embed LICENSE-MIT
var mitLicense string

//go:embed LICENSE-APACHE
var apacheLicense string

//go:embed THIRD_PARTY_NOTICES.md
var thirdPartyNotices string

// LicenseText includes the project license choices and third-party notices.
func LicenseText() string {
	return "ssjack\nLicense expression: MIT OR Apache-2.0\nChoose either project license; third-party terms remain applicable.\n\n" +
		mitLicense + "\n" + apacheLicense + "\n" + thirdPartyNotices
}
