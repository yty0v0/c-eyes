//go:build linux

package accountscan

import (
	"context"
	"os"
	"path/filepath"
	"slices"
)

const (
	passwdPath      = "/etc/passwd"
	groupPath       = "/etc/group"
	shadowPath      = "/etc/shadow"
	sudoersPath     = "/etc/sudoers"
	sudoersDirPath  = "/etc/sudoers.d"
	lastlogPath     = "/var/log/lastlog"
	authorizedLimit = 64
)

func collectAccounts(ctx context.Context) ([]AccountInfo, error) {
	_ = ctx

	passwdData, err := os.ReadFile(passwdPath)
	if err != nil {
		return nil, err
	}
	passwdEntries := parsePasswd(passwdData)

	groupData, _ := os.ReadFile(groupPath)
	userGroups, gidNames := parseGroupMembership(groupData)

	shadowMap := map[string]shadowEntry{}
	if shadowData, err := os.ReadFile(shadowPath); err == nil {
		shadowMap = parseShadow(shadowData, nowFn())
	}

	sudoRules := readSudoRules()
	lastlog := readLastlog(lastlogPath, passwdEntries)

	out := make([]AccountInfo, 0, len(passwdEntries))
	for _, entry := range passwdEntries {
		primaryGroup := gidNames[entry.GID]
		groups := mergeAndSortGroups(primaryGroup, userGroups[entry.Name])
		slices.Sort(groups)

		account := AccountInfo{
			UID:     int64Ptr(entry.UID),
			GID:     int64Ptr(entry.GID),
			Groups:  groups,
			Name:    strPtr(entry.Name),
			Home:    strPtr(entry.Home),
			Shell:   strPtr(entry.Shell),
			Comment: nullableString(entry.Comment),
			Root:    boolPtr(entry.UID == 0),
		}

		status := 1
		passwordSet := !isNoLoginShell(entry.Shell)
		if shadow, ok := shadowMap[entry.Name]; ok {
			if shadow.Disabled {
				status = 0
			}
			passwordSet = shadow.PasswordSet
			account.PwdMinDays = shadow.PwdMinDays
			account.PwdMaxDays = shadow.PwdMaxDays
			account.PwdWarnDays = shadow.PwdWarnDays
			account.PasswordInactiveDays = shadow.PasswordInactiveDays
			account.LastChangPwdTime = shadow.LastChangePwdTime
			account.ExpireTime = shadow.ExpireTime
			account.Expired = shadow.Expired
		}
		account.Status = intPtr(status)

		if info, ok := lastlog[entry.UID]; ok {
			account.LastLoginTime = info.Time
			account.LastLoginTTY = info.TTY
			account.LastLoginIP = info.IP
		}

		sshACL, keys := readSSHMetadata(entry.Home)
		account.SSHACL = sshACL
		account.AuthorizedKeys = keys

		loginStatus, accountLoginType, interactiveLoginType := deriveLinuxLoginModes(entry.Shell, passwordSet, len(keys) > 0)
		account.LoginStatus = intPtr(loginStatus)
		account.AccountLoginType = intPtr(accountLoginType)
		account.InteractiveLoginType = intPtr(interactiveLoginType)

		sudoAllowed, accesses := resolveSudo(entry.Name, groups, sudoRules)
		account.Sudo = boolPtr(sudoAllowed)
		account.SudoAccesses = accesses

		out = append(out, account)
	}
	return out, nil
}

func readSudoRules() []sudoRule {
	rules := make([]sudoRule, 0, 16)
	if data, err := os.ReadFile(sudoersPath); err == nil {
		rules = append(rules, parseSudoers(data)...)
	}
	if entries, err := os.ReadDir(sudoersDirPath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(sudoersDirPath, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			rules = append(rules, parseSudoers(data)...)
		}
	}
	return rules
}

func readSSHMetadata(home string) (*string, []AuthorizedKey) {
	if home == "" {
		return nil, nil
	}
	sshDir := filepath.Join(home, ".ssh")
	var acl *string
	if info, err := os.Stat(sshDir); err == nil {
		mode := formatPermMode(uint32(info.Mode().Perm()))
		acl = strPtr(mode)
	}

	authPath := filepath.Join(sshDir, "authorized_keys")
	data, err := os.ReadFile(authPath)
	if err != nil {
		return acl, nil
	}
	return acl, parseAuthorizedKeys(data, authorizedLimit)
}
