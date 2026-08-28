package store

import (
	"sort"

	"github.com/codejavu-llc/saase/v2/internal/model"
)

func Diff(before, after model.ScanReport) []model.Change {
	type entry struct {
		finding model.Finding
	}
	key := func(f model.Finding) string { return f.Target + "\x00" + f.ProviderID + "\x00" + f.Tenant }
	oldValues := make(map[string]entry)
	newValues := make(map[string]entry)
	for _, finding := range before.Findings {
		oldValues[key(finding)] = entry{finding: finding}
	}
	for _, finding := range after.Findings {
		newValues[key(finding)] = entry{finding: finding}
	}
	changes := make([]model.Change, 0)
	for id, value := range newValues {
		old, existed := oldValues[id]
		if !existed {
			afterConfidence := value.finding.Confidence
			changes = append(changes, model.Change{Type: model.ChangeAdded, Target: value.finding.Target, Provider: value.finding.Provider, Tenant: value.finding.Tenant, After: &afterConfidence})
		} else if old.finding.Confidence != value.finding.Confidence {
			beforeConfidence, afterConfidence := old.finding.Confidence, value.finding.Confidence
			changes = append(changes, model.Change{Type: model.ChangeConfidence, Target: value.finding.Target, Provider: value.finding.Provider, Tenant: value.finding.Tenant, Before: &beforeConfidence, After: &afterConfidence})
		}
	}
	for id, value := range oldValues {
		if _, exists := newValues[id]; !exists {
			beforeConfidence := value.finding.Confidence
			changes = append(changes, model.Change{Type: model.ChangeRemoved, Target: value.finding.Target, Provider: value.finding.Provider, Tenant: value.finding.Tenant, Before: &beforeConfidence})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Target != changes[j].Target {
			return changes[i].Target < changes[j].Target
		}
		if changes[i].Provider != changes[j].Provider {
			return changes[i].Provider < changes[j].Provider
		}
		return changes[i].Type < changes[j].Type
	})
	return changes
}
