package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"saase/services"
	"strings"
	"time"
)

const (
	colorDarkGreen = "\033[32m"
	colorYellow    = "\033[33m"
	colorRed       = "\033[31m"
	colorCyan      = "\033[36m"
	colorGray      = "\033[90m"
	colorBold      = "\033[1m"
	colorReset     = "\033[0m"

	// colorHit is the single uniform color used for every service name
	// when -v is NOT enabled.
	colorHit = "\033[32m"
)

// ansiEscape matches ANSI color/style escape sequences, stripped when
// writing to an -o output file so the file stays plain text.
var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

// outFile, when non-nil, receives a plain-text (no ANSI) mirror of
// everything written via write().
var outFile *os.File

func write(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Print(msg)
	if outFile != nil {
		fmt.Fprint(outFile, stripANSI(msg))
	}
}

const banner = `
   ███████╗ █████╗  █████╗ ███████╗███████╗
   ██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝
   ███████╗███████║███████║███████╗█████╗
   ╚════██║██╔══██║██╔══██║╚════██║██╔══╝
   ███████║██║  ██║██║  ██║███████║███████╗
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
        SaaS Attack Surface Enumerator
              by CodejaVu
`

// detectionKind describes how a service was fingerprinted.
type detectionKind int

const (
	kindSlugOnly detectionKind = iota // weak signal -> yellow
	kindViaSSO                        // strong signal -> dark green
	kindViaTXT                        // explicit DNS record signal -> custom label
)

// service represents a single checkable SaaS integration.
type service struct {
	names []string // first entry is canonical/display key, rest are aliases
	label string   // display name
	kind  detectionKind
	check func(domain, proxy string) bool
}

func printBanner() {
	write("%s%s%s\n", colorCyan, banner, colorReset)
}

func logInfo(format string, args ...interface{}) {
	write("%s[*]%s %s\n", colorGray, colorReset, fmt.Sprintf(format, args...))
}

func logHit(verbose bool, label string, kind detectionKind) {
	if !verbose {
		// Uniform color for every service name when -v is off.
		write("%s[+] %s%s\n", colorHit, label, colorReset)
		return
	}

	switch kind {
	case kindViaSSO:
		write("%s[+] %s - Via SSO%s\n", colorDarkGreen, label, colorReset)
	case kindViaTXT:
		write("%s[+] %s - Via TXT Record%s\n", colorCyan, label, colorReset)
	default:
		write("%s[+] %s - Slug Only%s\n", colorYellow, label, colorReset)
	}
}

// logError prints an error, but only when verbose mode is enabled.
func logError(verbose bool, format string, args ...interface{}) {
	if !verbose {
		return
	}
	write("%s[!]%s %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
}

// buildRegistry returns every known service check, in the same order
// they were originally wired up in main().
func buildRegistry() []service {
	return []service{
		{names: []string{"cisco webex", "ciscowebex", "webex"}, label: "Cisco Webex", kind: kindViaSSO, check: services.CheckCiscoWebex},
		{names: []string{"goto"}, label: "GoTo", kind: kindViaSSO, check: services.CheckGoTo},
		{names: []string{"loom"}, label: "Loom", kind: kindViaSSO, check: services.CheckLoom},
		{names: []string{"airtable"}, label: "Airtable", kind: kindViaSSO, check: services.CheckAirtable},
		{names: []string{"coda"}, label: "Coda", kind: kindViaSSO, check: services.CheckCoda},
		{names: []string{"atlassian"}, label: "Atlassian", kind: kindViaSSO, check: services.CheckAtlassian},
		{names: []string{"dropbox"}, label: "Dropbox", kind: kindViaSSO, check: services.CheckDropbox},
		{names: []string{"grammarly"}, label: "Grammarly", kind: kindViaSSO, check: services.CheckGrammarly},
		{names: []string{"notion"}, label: "Notion", kind: kindViaSSO, check: services.CheckNotion},
		{names: []string{"quip"}, label: "Quip", kind: kindViaSSO, check: services.CheckQuip},
		{names: []string{"smartsheet"}, label: "Smartsheet", kind: kindViaSSO, check: services.CheckSmartsheet},
		{names: []string{"asana"}, label: "Asana", kind: kindViaSSO, check: services.CheckAsana},
		{names: []string{"linear"}, label: "Linear", kind: kindViaSSO, check: services.CheckLinear},
		{names: []string{"rally uxr", "rallyuxr", "rally"}, label: "Rally UXR", kind: kindViaSSO, check: services.CheckRallyUXR},
		{names: []string{"hackerone"}, label: "HackerOne", kind: kindViaSSO, check: services.CheckHackerOne},
		{names: []string{"highspot"}, label: "Highspot", kind: kindViaSSO, check: services.CheckHighspot},
		{names: []string{"intercom"}, label: "Intercom", kind: kindViaSSO, check: services.CheckIntercom},
		{names: []string{"canva"}, label: "Canva", kind: kindViaSSO, check: services.CheckCanva},
		{names: []string{"figma"}, label: "Figma", kind: kindViaSSO, check: services.CheckFigma},
		{names: []string{"webflow"}, label: "Webflow", kind: kindViaSSO, check: services.CheckWebflow},
		{names: []string{"docker"}, label: "Docker", kind: kindViaSSO, check: services.CheckDocker},
		{names: []string{"dynatrace"}, label: "Dynatrace", kind: kindViaSSO, check: services.CheckDynatrace},
		{names: []string{"logz.io", "logzio"}, label: "Logz.io", kind: kindViaSSO, check: services.CheckLogzio},
		{names: []string{"akamai"}, label: "Akamai", kind: kindViaSSO, check: services.CheckAkamai},
		{names: []string{"stripe"}, label: "Stripe", kind: kindViaSSO, check: services.CheckStripe},
		{names: []string{"segment"}, label: "Segment", kind: kindViaSSO, check: services.CheckSegment},
		{names: []string{"docusign"}, label: "DocuSign", kind: kindViaSSO, check: services.CheckDocusign},
		{names: []string{"teamviewer"}, label: "TeamViewer", kind: kindViaSSO, check: services.CheckTeamViewer},
		{names: []string{"elastic"}, label: "Elastic", kind: kindViaSSO, check: services.CheckElastic},
		{names: []string{"microsoft"}, label: "Microsoft", kind: kindViaSSO, check: services.CheckMicrosoft},
		{names: []string{"google"}, label: "Google", kind: kindViaSSO, check: services.CheckGoogle},
		{names: []string{"jamf"}, label: "Jamf", kind: kindViaSSO, check: services.CheckJamf},
		{names: []string{"adobe"}, label: "Adobe", kind: kindViaSSO, check: services.CheckAdobe},
		{names: []string{"cloudflare"}, label: "Cloudflare", kind: kindViaSSO, check: services.CheckCloudflare},
		{names: []string{"algolia"}, label: "Algolia", kind: kindViaSSO, check: services.CheckAlgolia},
		{names: []string{"dialpad"}, label: "Dialpad", kind: kindViaSSO, check: services.CheckDialpad},
		{names: []string{"lucid"}, label: "Lucid", kind: kindViaSSO, check: services.CheckLucid},
		{names: []string{"pluralsight"}, label: "Pluralsight", kind: kindViaSSO, check: services.CheckPluralsight},
		{names: []string{"doodle"}, label: "Doodle", kind: kindViaSSO, check: services.CheckDoodle},

		{names: []string{"dixa"}, label: "Dixa", kind: kindSlugOnly, check: services.CheckDixa},
		{names: []string{"frontapp", "front"}, label: "Frontapp", kind: kindSlugOnly, check: services.CheckFrontApp},
		{names: []string{"gorgias"}, label: "Gorgias", kind: kindSlugOnly, check: services.CheckGorgias},
		{names: []string{"sketch"}, label: "Sketch", kind: kindSlugOnly, check: services.CheckSketch},
		{names: []string{"postman"}, label: "Postman", kind: kindSlugOnly, check: services.CheckPostman},
		{names: []string{"sentry"}, label: "Sentry", kind: kindSlugOnly, check: services.CheckSentry},
		{names: []string{"amplitude"}, label: "Amplitude", kind: kindSlugOnly, check: services.CheckAmplitude},
		{names: []string{"klaviyo"}, label: "Klaviyo", kind: kindSlugOnly, check: services.CheckKlaviyo},
		{names: []string{"cvent"}, label: "Cvent", kind: kindSlugOnly, check: services.CheckCvent},
		{names: []string{"planetscale"}, label: "PlanetScale", kind: kindSlugOnly, check: services.CheckPlanetScale},
		{names: []string{"monday"}, label: "Monday.com", kind: kindSlugOnly, check: services.CheckMonday},
		{names: []string{"slack"}, label: "Slack", kind: kindSlugOnly, check: services.CheckSlack},
		{names: []string{"freshdesk"}, label: "Freshdesk", kind: kindSlugOnly, check: services.CheckFreshdesk},
		{names: []string{"freshchat"}, label: "Freshchat", kind: kindSlugOnly, check: services.CheckFreshchat},
		{names: []string{"freshservice"}, label: "Freshservice", kind: kindSlugOnly, check: services.CheckFreshservice},
		{names: []string{"freshcaller"}, label: "Freshcaller", kind: kindSlugOnly, check: services.CheckFreshcaller},
		{names: []string{"freshworks"}, label: "Freshworks", kind: kindSlugOnly, check: services.CheckFreshworks},
		{names: []string{"salesforcelightning"}, label: "Salesforce Lightning", kind: kindSlugOnly, check: services.CheckSalesforceLightning},
		{names: []string{"salesforcelightningsandbox"}, label: "Salesforce Lightning Sandbox", kind: kindSlugOnly, check: services.CheckSalesforceLightningSandbox},
		{names: []string{"salesforce"}, label: "Salesforce", kind: kindSlugOnly, check: services.CheckSalesforce},
		{names: []string{"salesforcesite"}, label: "Salesforce Site", kind: kindSlugOnly, check: services.CheckSalesforceSite},
		{names: []string{"salesforcesites"}, label: "Salesforce Sites", kind: kindSlugOnly, check: services.CheckSalesforceSites},
		{names: []string{"salesforceforce"}, label: "Salesforce Force", kind: kindSlugOnly, check: services.CheckSalesforceForce},
		{names: []string{"seismic"}, label: "Seismic", kind: kindSlugOnly, check: services.CheckSeismic},
		{names: []string{"zendesk"}, label: "Zendesk", kind: kindSlugOnly, check: services.CheckZendesk},
		{names: []string{"kustomer"}, label: "Kustomer", kind: kindSlugOnly, check: services.CheckKustomer},
		{names: []string{"bambbohr"}, label: "BambboHR", kind: kindSlugOnly, check: services.CheckBambooHR},
		{names: []string{"namely"}, label: "Namely", kind: kindSlugOnly, check: services.CheckNamely},
		{names: []string{"paylocity"}, label: "Paylocity", kind: kindSlugOnly, check: services.CheckPaylocity},
		{names: []string{"rippling"}, label: "Rippling", kind: kindSlugOnly, check: services.CheckRippling},
		{names: []string{"netlify"}, label: "Netlify", kind: kindSlugOnly, check: services.CheckNetlify},
		{names: []string{"auth0"}, label: "Auth0", kind: kindSlugOnly, check: services.CheckAuth0},
		{names: []string{"okta"}, label: "Okta", kind: kindSlugOnly, check: services.CheckOkta},
		{names: []string{"sumologic"}, label: "Sumologic", kind: kindSlugOnly, check: services.CheckSumologic},
		{names: []string{"activecampaign"}, label: "ActiveCampaign", kind: kindSlugOnly, check: services.CheckActiveCampaign},
		{names: []string{"sharefile"}, label: "Sharefile", kind: kindSlugOnly, check: services.CheckSharefile},
		{names: []string{"talentlms"}, label: "TalentLMS", kind: kindSlugOnly, check: services.CheckTalentLMS},
		{names: []string{"calendly"}, label: "Calendly", kind: kindSlugOnly, check: services.CheckCalendly},
		{names: []string{"gainsight"}, label: "Gainsight", kind: kindSlugOnly, check: services.CheckGainsight},
		{names: []string{"vercel"}, label: "Vercel", kind: kindSlugOnly, check: services.CheckVercel},
		{names: []string{"contentful"}, label: "Contentful", kind: kindSlugOnly, check: services.CheckContentful},
		{names: []string{"onelogin"}, label: "Onelogin", kind: kindSlugOnly, check: services.CheckOnelogin},
		{names: []string{"laceworks"}, label: "Laceworks", kind: kindSlugOnly, check: services.CheckLaceworks},
		{names: []string{"chargebee"}, label: "Chargebee", kind: kindSlugOnly, check: services.CheckChargebee},
		{names: []string{"wistia"}, label: "Wistia", kind: kindSlugOnly, check: services.CheckWistia},
	}
}

// matches reports whether this service should run, given a target set.
// A nil/empty target set means "run everything".
func (s service) matches(targets map[string]bool) bool {
	if len(targets) == 0 {
		return true
	}
	for _, n := range s.names {
		if targets[n] {
			return true
		}
	}
	return false
}

// loadConfigFile reads a newline-delimited list of service names,
// ignoring blank lines and lines starting with '#'.
func loadConfigFile(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	targets := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets[line] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

func main() {
	domainPtr := flag.String("d", "", "target domain to fingerprint")
	proxyPtr := flag.String("x", "", "proxy to route requests through")
	servicePtr := flag.String("s", "", "single service name to check")
	configPtr := flag.String("c", "", "config file with one service name per line")
	verbosePtr := flag.Bool("v", false, "verbose: show detection method (Slug Only / Via SSO) and errors")
	outPtr := flag.String("o", "", "write a plain-text copy of the output to this file")
	flag.Parse()

	if *outPtr != "" {
		f, err := os.Create(*outPtr)
		if err != nil {
			fmt.Printf("%s[!]%s failed to create output file %q: %v\n", colorRed, colorReset, *outPtr, err)
			os.Exit(1)
		}
		outFile = f
		defer outFile.Close()
	}

	printBanner()

	if *domainPtr == "" {
		logError(*verbosePtr, "no target specified, use -d <domain>")
		os.Exit(1)
	}

	// Build the set of requested service names from -s and/or -c.
	targets := make(map[string]bool)

	if *configPtr != "" {
		fileTargets, err := loadConfigFile(*configPtr)
		if err != nil {
			logError(*verbosePtr, "failed to read config file %q: %v", *configPtr, err)
			os.Exit(1)
		}
		for k := range fileTargets {
			targets[k] = true
		}
	}

	if *servicePtr != "" {
		targets[strings.ToLower(strings.TrimSpace(*servicePtr))] = true
	}

	runAll := len(targets) == 0

	logInfo("target      : %s%s%s", colorBold, *domainPtr, colorReset)
	if *proxyPtr != "" {
		logInfo("proxy       : %s", *proxyPtr)
	}
	if runAll {
		logInfo("mode        : full sweep (%d services)", len(buildRegistry()))
	} else {
		logInfo("mode        : targeted (%d service(s) loaded)", len(targets))
	}
	logInfo("verbose     : %v", *verbosePtr)
	if *outPtr != "" {
		logInfo("output file : %s", *outPtr)
	}
	logInfo("starting enumeration...")
	write("%s\n", strings.Repeat("-", 46))

	start := time.Now()
	hits := 0

	originalStdout := os.Stdout

	// Execute TXT Discovery validation prior to sequential pipeline runs
	discoveredViaTXT := make(map[string]bool)
	txtServices := services.CheckTXTServices(*domainPtr)
	
	for _, rawSvc := range txtServices {
		normSvc := strings.ToLower(rawSvc)
		
		// Skip duplicate discoveries inside TXT records
		if discoveredViaTXT[normSvc] {
			continue
		}
		
		discoveredViaTXT[normSvc] = true
		logHit(*verbosePtr, rawSvc, kindViaTXT)
		hits++
	}

	for _, svc := range buildRegistry() {
		if !svc.matches(targets) {
			continue
		}

		// Evaluate cancellation criteria if service identifier has been checked via TXT mapping matches
		skipService := false
		for _, name := range svc.names {
			if discoveredViaTXT[name] {
				skipService = true
				break
			}
		}
		if skipService {
			continue
		}

		// Silence module standard output unless verbose mode is enabled
		if !*verbosePtr {
			os.Stdout = nil
		}

		isHit := svc.check(*domainPtr, *proxyPtr)

		// Restore original stdout execution context
		if !*verbosePtr {
			os.Stdout = originalStdout
		}

		if isHit {
			logHit(*verbosePtr, svc.label, svc.kind)
			hits++
		}
	}

	write("%s\n", strings.Repeat("-", 46))
	elapsed := time.Since(start).Round(time.Millisecond)
	if hits == 0 {
		logInfo("scan complete: %s0%s services detected in %s", colorRed, colorReset, elapsed)
	} else {
		logInfo("scan complete: %s%d%s service(s) detected in %s", colorBold, hits, colorReset, elapsed)
	}
}
