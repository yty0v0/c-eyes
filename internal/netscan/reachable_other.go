//go:build !windows && !linux

package netscan

func collectRouteCandidates() ([]reachabilitySignal, []string) {
	return []reachabilitySignal{}, []string{"reachableSegments: route collector is not implemented for this platform"}
}

func collectConnectionCandidates() ([]reachabilitySignal, []string) {
	return []reachabilitySignal{}, []string{"reachableSegments: connection collector is not implemented for this platform"}
}
