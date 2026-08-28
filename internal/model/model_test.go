package model

import "testing"

func TestConfidenceRank(t *testing.T) {
	ordered := []Confidence{ConfidenceUnknown, ConfidenceLow, ConfidenceMedium, ConfidenceHigh, ConfidenceConfirmed}
	for index, confidence := range ordered {
		if got := confidence.Rank(); got != index {
			t.Fatalf("%s rank = %d, want %d", confidence, got, index)
		}
	}
	if got := Confidence("future").Rank(); got != 0 {
		t.Fatalf("unknown rank = %d", got)
	}
}
