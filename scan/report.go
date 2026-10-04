package scan

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
)

func WriteText(w io.Writer, findings []Finding) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tLOCATION\tCOMMIT\tSECRET\tFINGERPRINT")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s:%d\t%s\t%s\t%s\n",
			f.RuleID, f.File, f.Line, shortCommit(f.Commit), f.Redacted, f.Fingerprint)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d finding(s)\n", len(findings))
	return err
}

func shortCommit(c string) string {
	if c == "" {
		return "-"
	}
	return c[:min(len(c), 8)]
}

func WriteJSON(w io.Writer, findings []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(nonNil(findings))
}

func nonNil(findings []Finding) []Finding {
	if findings == nil {
		return []Finding{}
	}
	return findings
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// WriteSARIF: SARIF 2.1.0 for GH code scanning.
func WriteSARIF(w io.Writer, findings []Finding, rules []Rule) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "leakscan",
			InformationURI: "https://github.com/rezmoss/leakscan",
		}},
		Results: []sarifResult{},
	}
	for _, r := range rules {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID: r.ID, ShortDescription: sarifMessage{Text: r.Description},
		})
	}
	for _, f := range findings {
		msg := fmt.Sprintf("%s found: %s", f.Description, f.Redacted)
		if f.Commit != "" {
			msg += " (commit " + shortCommit(f.Commit) + ")"
		}
		run.Results = append(run.Results, sarifResult{
			RuleID:  f.RuleID,
			Level:   "error",
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.File},
				Region:           sarifRegion{StartLine: max(f.Line, 1), StartColumn: f.Column},
			}}},
			PartialFingerprints: map[string]string{"leakscan/v1": f.Fingerprint},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []sarifRun{run},
	})
}

func SortFindings(findings []Finding) {
	slices.SortStableFunc(findings, func(a, b Finding) int {
		return cmp.Or(
			strings.Compare(a.File, b.File),
			cmp.Compare(a.Line, b.Line),
			strings.Compare(a.RuleID, b.RuleID),
		)
	})
}
