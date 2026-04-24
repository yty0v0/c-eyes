package accountscan

import (
	"context"

	"edrsystem/internal/processscan"
)

var collectAccountsFn = collectAccounts

// Scan collects and filters system accounts.
func Scan(ctx context.Context, params AccountScanParams) (AccountScanResult, error) {
	accounts, err := collectAccountsFn(ctx)
	if err != nil {
		return AccountScanResult{}, err
	}

	host, _ := processscan.GetHostInfo()
	total := len(accounts)
	for i := range accounts {
		applyHost(&accounts[i], host)
		normalizeDefaults(&accounts[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_accounts")
		}
	}

	filtered := ApplyFilters(accounts, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return AccountScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func applyHost(account *AccountInfo, host processscan.HostInfo) {
	if host.DisplayIP != nil {
		account.DisplayIP = host.DisplayIP
		account.ConnectionIP = host.DisplayIP
	}
	if len(host.ExternalIPs) > 0 {
		account.ExternalIPList = append([]string(nil), host.ExternalIPs...)
	}
	if len(host.InternalIPs) > 0 {
		account.InternalIPList = append([]string(nil), host.InternalIPs...)
	}
	if host.BizGroupID != nil {
		account.BizGroupID = host.BizGroupID
	}
	if host.BizGroup != nil {
		account.BizGroup = host.BizGroup
	}
	if host.Remark != nil {
		account.Remark = host.Remark
	}
	if len(host.HostTagList) > 0 {
		account.HostTagList = append([]string(nil), host.HostTagList...)
	}
	if host.Hostname != "" {
		account.Hostname = strPtr(host.Hostname)
	}
}

func normalizeDefaults(account *AccountInfo) {
	if account.Groups == nil {
		account.Groups = []string{}
	}
	if account.HostTagList == nil {
		account.HostTagList = []string{}
	}
	if account.ExternalIPList == nil {
		account.ExternalIPList = []string{}
	}
	if account.InternalIPList == nil {
		account.InternalIPList = []string{}
	}
	if account.SudoAccesses == nil {
		account.SudoAccesses = []SudoAccess{}
	}
	if account.AuthorizedKeys == nil {
		account.AuthorizedKeys = []AuthorizedKey{}
	}
}
