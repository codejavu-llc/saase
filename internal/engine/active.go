package engine

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
)

type activeProbe struct {
	ProviderID string
	Kind       model.Signal
	URL        string
	Domain     bool
	Statuses   []int
	Reject     []string
	Require    []string
}

var activeProbes = []activeProbe{
	{ProviderID: "slack", Kind: model.SignalTenant, URL: "https://%s.slack.com/", Reject: []string{"workspace doesn't exist", "workspace does not exist", "?redir="}},
	{ProviderID: "atlassian", Kind: model.SignalTenant, URL: "https://%s.atlassian.net/", Reject: []string{"site not found", "cloud site is currently unavailable"}},
	{ProviderID: "zendesk", Kind: model.SignalTenant, URL: "https://%s.zendesk.com/", Reject: []string{"help-center-closed", "no help center exists"}},
	{ProviderID: "freshdesk", Kind: model.SignalTenant, URL: "https://%s.freshdesk.com/", Reject: []string{"domain not found", "portal not found"}},
	{ProviderID: "freshservice", Kind: model.SignalTenant, URL: "https://%s.freshservice.com/", Reject: []string{"domain not found", "account not found"}},
	{ProviderID: "freshworks", Kind: model.SignalTenant, URL: "https://%s.freshworks.com/", Reject: []string{"domain not found", "account not found"}},
	{ProviderID: "monday-com", Kind: model.SignalTenant, URL: "https://%s.monday.com/", Reject: []string{"account not found", "doesn't exist"}},
	{ProviderID: "okta", Kind: model.SignalTenant, URL: "https://%s.okta.com/", Reject: []string{"404 not found", "org not found"}},
	{ProviderID: "onelogin", Kind: model.SignalTenant, URL: "https://%s.onelogin.com/", Reject: []string{"account not found", "invalid subdomain"}},
	{ProviderID: "salesforce", Kind: model.SignalTenant, URL: "https://%s.my.salesforce.com/", Reject: []string{"server not found", "domain is not available"}},
	{ProviderID: "bamboohr", Kind: model.SignalTenant, URL: "https://%s.bamboohr.com/", Reject: []string{"company not found", "account not found"}},
	{ProviderID: "netlify", Kind: model.SignalTenant, URL: "https://%s.netlify.app/", Reject: []string{"not found - request id", "page not found"}},
	{ProviderID: "activecampaign", Kind: model.SignalTenant, URL: "https://%s.activehosted.com/", Reject: []string{"account not found", "site not found"}},
	{ProviderID: "calendly", Kind: model.SignalTenant, URL: "https://calendly.com/%s", Reject: []string{"page not found", "not found | calendly"}},
	{ProviderID: "talentlms", Kind: model.SignalTenant, URL: "https://%s.talentlms.com/", Reject: []string{"domain not found", "portal not found"}},
	{ProviderID: "sumo-logic", Kind: model.SignalTenant, URL: "https://%s.sumologic.com/", Reject: []string{"site not found", "account not found"}},
	{ProviderID: "microsoft-365", Kind: model.SignalSSO, URL: "https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", Domain: true, Statuses: []int{200}, Require: []string{"authorization_endpoint"}, Reject: []string{"invalid_tenant"}},
	{ProviderID: "google-workspace", Kind: model.SignalSSO, URL: "https://www.google.com/a/%s/ServiceLogin", Domain: true, Statuses: []int{302}},
	{ProviderID: "jamf", Kind: model.SignalSSO, URL: "https://org-region-service.jamf.com/v2/region/domain/%s", Domain: true, Statuses: []int{200}, Reject: []string{"domain not found"}},
	{ProviderID: "sharefile", Kind: model.SignalTenant, URL: "https://auth.sharefile.io/api/SubdomainAvailability?subdomain=%s", Statuses: []int{200}, Require: []string{`"issubdomainavailable":false`}},
	{ProviderID: "wistia", Kind: model.SignalSSO, URL: "https://app.wistia.com/auth/sso/validate?account_key=%s", Statuses: []int{200}, Require: []string{`"found":true`}},
	{ProviderID: "dialpad", Kind: model.SignalSSO, URL: "https://dialpad.com/saml/login/okta/%s", Domain: true, Reject: []string{"bad_saml_config"}},
	{ProviderID: "algolia", Kind: model.SignalSSO, URL: "https://dashboard.algolia.com/auth/sso?email=recon@%s", Domain: true, Reject: []string{"single sign-on is not enabled"}},
	{ProviderID: "doodle", Kind: model.SignalSSO, URL: "https://api.doodle.com/svc-sso-saml/saml/login?domain=%s&redirectUrl=https://doodle.com/dashboard", Domain: true, Statuses: []int{200}},
	{ProviderID: "contentful", Kind: model.SignalSSO, URL: "https://be.contentful.com/users/sso/organization?sso_name=%s", Statuses: []int{200}},
	{ProviderID: "gainsight", Kind: model.SignalTenant, URL: "https://auth.gainsightcloud.com/client-by-domain?fqdn=%s.gainsightcloud.com", Statuses: []int{200}, Reject: []string{"domain doesn't exist"}},
	{ProviderID: "lacework", Kind: model.SignalTenant, URL: "https://login.lacework.net/api/v1/accounts/acnt_name/%s", Statuses: []int{200}},
	{ProviderID: "freshchat", Kind: model.SignalTenant, URL: "https://%s.freshchat.com/app/public/user_info/v3", Statuses: []int{200}, Reject: []string{"api.freshworks.com"}},
	{ProviderID: "auth0", Kind: model.SignalTenant, URL: "https://%s.auth0.com/test535", Reject: []string{"unknown host"}},
	{ProviderID: "kustomer", Kind: model.SignalTenant, URL: "https://%s.api.kustomerapp.com/p/v1/auth/settings", Statuses: []int{200}},
	{ProviderID: "chargebee", Kind: model.SignalSSO, URL: "https://app.chargebee.com/saml/validate_login?domain=%s", Statuses: []int{200}, Reject: []string{"site not found"}},
	{ProviderID: "lucid", Kind: model.SignalSSO, URL: "https://lucid.app/saml/sso/%s", Domain: true, Reject: []string{"/users/login"}},
}

func ActiveProviderIDs() []string {
	ids := make([]string, 0, len(activeProbes))
	for _, probe := range activeProbes {
		ids = append(ids, probe.ProviderID)
	}
	sort.Strings(ids)
	return ids
}

func (s *Scanner) activeFindings(ctx context.Context, t target.Target, selected map[string]bool) ([]model.Finding, []model.ProbeError) {
	var findings []model.Finding
	var probeErrors []model.ProbeError
	for _, probe := range activeProbes {
		if len(selected) > 0 && !selected[probe.ProviderID] {
			continue
		}
		provider, ok := s.catalog.Provider(probe.ProviderID)
		if !ok {
			continue
		}
		arguments := t.SlugCandidates
		if probe.Domain {
			arguments = []string{t.Apex}
		}
		for _, argument := range arguments {
			address := fmt.Sprintf(probe.URL, argument)
			result, err := s.doHTTP(ctx, provider.ID, http.MethodGet, address)
			if err != nil {
				probeErrors = append(probeErrors, model.ProbeError{Target: t.Apex, Detector: "active/" + provider.ID, Subject: address, Kind: "network", Message: err.Error()})
				continue
			}
			if result.StatusCode == http.StatusTooManyRequests {
				probeErrors = append(probeErrors, model.ProbeError{Target: t.Apex, Detector: "active/" + provider.ID, Subject: address, Kind: "rate_limited", Message: "provider returned HTTP 429"})
				break
			}
			if result.StatusCode >= 400 || (len(probe.Statuses) > 0 && !allowedStatus(result.StatusCode, probe.Statuses)) {
				continue
			}
			haystack := strings.ToLower(result.Body + "\n" + result.Header.Get("Location"))
			if containsAny(haystack, probe.Reject) || (len(probe.Require) > 0 && !containsAny(haystack, probe.Require)) {
				continue
			}
			confidence := model.ConfidenceMedium
			if result.StatusCode == http.StatusOK && (len(probe.Require) > 0 || probe.Kind == model.SignalSSO) {
				confidence = model.ConfidenceHigh
			}
			found := model.Finding{
				SchemaVersion: model.SchemaVersion, Target: t.Apex, ProviderID: provider.ID, Provider: provider.Name,
				Category: provider.Category, Description: provider.Description, Website: provider.Website, Impact: provider.Impact,
				Tenant: address, Confidence: confidence, Detector: "active/tenant-v1", ObservedAt: time.Now().UTC(), LatencyMS: result.Latency.Milliseconds(),
				RiskLead: "public_tenant_endpoint", Evidence: []model.Evidence{{Signal: probe.Kind, Subject: address, Value: fmt.Sprintf("HTTP %d", result.StatusCode)}},
			}
			findings = append(findings, s.observeFinding(found))
			break
		}
	}
	return findings, probeErrors
}

func allowedStatus(status int, allowed []int) bool {
	for _, value := range allowed {
		if status == value {
			return true
		}
	}
	return false
}

func containsAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(value, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}
