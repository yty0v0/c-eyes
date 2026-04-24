package riskanalysis

import (
	"strings"
	"unicode"
)

const defaultMatchedSeverity = 40

type severityProfile struct {
	severity int
	terms    []string
}

var severityFallbackProfiles = []severityProfile{
	{
		severity: 95,
		terms: []string{
			"ransom",
			"ransomware",
			"cryptolocker",
			"wannacry",
			"lockbit",
			"blackmatter",
			"darkside",
			"babuk",
			"sodinokibi",
			"gandcrab",
			"phobos",
			"petya",
			"cerber",
			"zeppelin",
		},
	},
	{
		severity: 90,
		terms: []string{
			"webshell",
			"cobaltstrike",
			"cobalt strike",
			"beacon",
			"mimikatz",
			"lsadump",
			"trojan",
			"backdoor",
			"rat",
			"rootkit",
			"keylogger",
			"stealer",
			"credential",
			"apt",
			"c2",
			"rekoobe",
		},
	},
	{
		severity: 85,
		terms: []string{
			"botnet",
			"worm",
			"dropper",
			"loader",
			"malware",
			"malw",
			"shellcode",
			"php proxy",
			"aspx proxy",
		},
	},
	{
		severity: 80,
		terms: []string{
			"coinminer",
			"cryptominer",
			"cryptojack",
			"miner",
			"xmrig",
			"wannamine",
		},
	},
	{
		severity: 75,
		terms: []string{
			"hacktool",
			"hktl",
		},
	},
}

func fallbackSeverity(ruleName string, tags []string) int {
	tokens := make(map[string]struct{})
	addSeverityTokens(tokens, ruleName)
	for _, tag := range tags {
		addSeverityTokens(tokens, tag)
	}
	if len(tokens) == 0 {
		return 0
	}

	best := 0
	for _, profile := range severityFallbackProfiles {
		for _, term := range profile.terms {
			if hasSeverityTerm(tokens, term) {
				if profile.severity > best {
					best = profile.severity
				}
				break
			}
		}
	}
	if best > 0 {
		return best
	}
	return defaultMatchedSeverity
}

func hasSeverityTerm(tokens map[string]struct{}, term string) bool {
	parts := tokenizeSeverityText(term)
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if _, ok := tokens[part]; !ok {
			return false
		}
	}
	return true
}

func addSeverityTokens(tokens map[string]struct{}, value string) {
	for _, token := range tokenizeSeverityText(value) {
		tokens[token] = struct{}{}
	}
}

func tokenizeSeverityText(value string) []string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return nil
	}

	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		b.WriteByte(' ')
	}
	return strings.Fields(b.String())
}
