package accountscan

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type passwdEntry struct {
	Name    string
	UID     int64
	GID     int64
	Comment string
	Home    string
	Shell   string
}

type shadowEntry struct {
	Disabled             bool
	PasswordSet          bool
	PwdMinDays           *int
	PwdMaxDays           *int
	PwdWarnDays          *int
	PasswordInactiveDays *int
	LastChangePwdTime    *time.Time
	ExpireTime           *time.Time
	Expired              *bool
}

type sudoRule struct {
	Principal string
	RunAs     string
	Command   string
}

type lastlogEntry struct {
	Time *time.Time
	TTY  *string
	IP   *string
}

func parsePasswd(data []byte) []passwdEntry {
	lines := splitLines(string(data))
	out := make([]passwdEntry, 0, len(lines))
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			continue
		}
		gid, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, passwdEntry{
			Name:    strings.TrimSpace(parts[0]),
			UID:     uid,
			GID:     gid,
			Comment: strings.TrimSpace(parts[4]),
			Home:    strings.TrimSpace(parts[5]),
			Shell:   strings.TrimSpace(parts[6]),
		})
	}
	return out
}

func parseGroupMembership(data []byte) (map[string][]string, map[int64]string) {
	lines := splitLines(string(data))
	userGroups := make(map[string][]string)
	gidNames := make(map[int64]string)
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		groupName := strings.TrimSpace(parts[0])
		gid, err := strconv.ParseInt(parts[2], 10, 64)
		if err == nil {
			gidNames[gid] = groupName
		}
		for _, member := range strings.Split(parts[3], ",") {
			member = strings.TrimSpace(member)
			if member == "" {
				continue
			}
			if !stringInSlice(groupName, userGroups[member]) {
				userGroups[member] = append(userGroups[member], groupName)
			}
		}
	}
	return userGroups, gidNames
}

func parseShadow(data []byte, now time.Time) map[string]shadowEntry {
	lines := splitLines(string(data))
	out := make(map[string]shadowEntry, len(lines))
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 9 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		passwd := strings.TrimSpace(parts[1])
		entry := shadowEntry{
			Disabled:    isDisabledShadowPassword(passwd),
			PasswordSet: isPasswordSet(passwd),
		}
		entry.LastChangePwdTime = daysFieldToTime(parts[2])
		entry.PwdMinDays = daysFieldToInt(parts[3])
		entry.PwdMaxDays = daysFieldToInt(parts[4])
		entry.PwdWarnDays = daysFieldToInt(parts[5])
		entry.PasswordInactiveDays = daysFieldToInt(parts[6])
		entry.ExpireTime = daysFieldToTime(parts[7])
		if entry.ExpireTime != nil {
			expired := entry.ExpireTime.Before(now)
			entry.Expired = &expired
		}
		out[name] = entry
	}
	return out
}

func parseAuthorizedKeys(data []byte, max int) []AuthorizedKey {
	lines := splitLines(string(data))
	out := make([]AuthorizedKey, 0, len(lines))
	for _, line := range lines {
		if max > 0 && len(out) >= max {
			break
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		keyType := fields[0]
		keyValue := fields[1]
		var comment *string
		if len(fields) > 2 {
			comment = strPtr(strings.Join(fields[2:], " "))
		}
		sum := md5.Sum([]byte(keyValue))
		md5Hex := hex.EncodeToString(sum[:])
		out = append(out, AuthorizedKey{
			EncryptType: strPtr(keyType),
			Comment:     comment,
			Value:       strPtr(keyValue),
			MD5:         strPtr(md5Hex),
		})
	}
	return out
}

func parseSudoers(data []byte) []sudoRule {
	lines := splitLines(string(data))
	out := make([]sudoRule, 0, len(lines))
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Defaults") ||
			strings.HasPrefix(line, "User_Alias") ||
			strings.HasPrefix(line, "Runas_Alias") ||
			strings.HasPrefix(line, "Host_Alias") ||
			strings.HasPrefix(line, "Cmnd_Alias") ||
			strings.HasPrefix(line, "@") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		eqIdx := strings.Index(line, "=")
		if eqIdx <= 0 {
			continue
		}
		principal := strings.TrimSpace(fields[0])
		right := strings.TrimSpace(line[eqIdx+1:])
		runAs := "ALL"
		if strings.HasPrefix(right, "(") {
			end := strings.Index(right, ")")
			if end > 1 {
				runAs = strings.TrimSpace(right[1:end])
				right = strings.TrimSpace(right[end+1:])
			}
		}
		command := strings.TrimSpace(right)
		if principal == "" || command == "" {
			continue
		}
		out = append(out, sudoRule{
			Principal: principal,
			RunAs:     runAs,
			Command:   command,
		})
	}
	return out
}

func resolveSudo(user string, groups []string, rules []sudoRule) (bool, []SudoAccess) {
	if user == "" || len(rules) == 0 {
		return false, nil
	}
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		groupSet[g] = struct{}{}
	}

	allowed := false
	accesses := make([]SudoAccess, 0, 2)
	for _, rule := range rules {
		matched := false
		if strings.EqualFold(rule.Principal, user) {
			matched = true
		} else if strings.HasPrefix(rule.Principal, "%") {
			group := strings.TrimPrefix(rule.Principal, "%")
			_, matched = groupSet[group]
		}
		if !matched {
			continue
		}
		allowed = true
		accesses = append(accesses, SudoAccess{
			Shell: strPtr(rule.Command),
			User:  strPtr(rule.RunAs),
		})
	}
	return allowed, accesses
}

func parseLastlogRecord(data []byte) lastlogEntry {
	if len(data) != 296 && len(data) != 292 {
		return lastlogEntry{}
	}
	var rawTime int64
	timeBytes := 8
	if len(data) == 292 {
		rawTime = int64(binary.LittleEndian.Uint32(data[:4]))
		timeBytes = 4
	} else {
		rawTime = int64(binary.LittleEndian.Uint64(data[:8]))
	}
	if rawTime <= 0 {
		return lastlogEntry{}
	}
	ts := time.Unix(rawTime, 0)
	tty := cleanCStr(data[timeBytes : timeBytes+32])
	host := cleanCStr(data[timeBytes+32 : timeBytes+32+256])
	entry := lastlogEntry{Time: &ts}
	if tty != "" {
		entry.TTY = strPtr(tty)
	}
	if host != "" {
		entry.IP = strPtr(host)
	}
	return entry
}

func isDisabledShadowPassword(passwd string) bool {
	if passwd == "" {
		return true
	}
	return strings.HasPrefix(passwd, "!") || strings.HasPrefix(passwd, "*")
}

func isPasswordSet(passwd string) bool {
	if passwd == "" {
		return false
	}
	if passwd == "!" || passwd == "*" || passwd == "!!" {
		return false
	}
	return !isDisabledShadowPassword(passwd)
}

func daysFieldToInt(v string) *int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return &n
}

func daysFieldToTime(v string) *time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	days, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil
	}
	t := time.Unix(days*24*60*60, 0)
	return &t
}

func cleanCStr(buf []byte) string {
	i := strings.IndexByte(string(buf), 0)
	if i >= 0 {
		buf = buf[:i]
	}
	return strings.TrimSpace(string(buf))
}

func splitLines(input string) []string {
	raw := strings.Split(input, "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func mergeAndSortGroups(primary string, extra []string) []string {
	seen := make(map[string]struct{}, len(extra)+1)
	out := make([]string, 0, len(extra)+1)
	if primary != "" {
		seen[primary] = struct{}{}
		out = append(out, primary)
	}
	for _, g := range extra {
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

func deriveLinuxLoginModes(shell string, passwordSet bool, hasKey bool) (loginStatus int, accountLoginType int, interactiveLoginType int) {
	nonInteractive := isNoLoginShell(shell)
	if nonInteractive {
		if hasKey && passwordSet {
			return 1, 3, 1
		}
		if hasKey {
			return 1, 1, 1
		}
		if passwordSet {
			return 1, 2, 1
		}
		return 0, 0, 0
	}
	if hasKey && passwordSet {
		return 3, 3, 2
	}
	if hasKey {
		return 2, 1, 2
	}
	if passwordSet {
		return 2, 2, 2
	}
	return 0, 0, 0
}

func isNoLoginShell(shell string) bool {
	s := strings.TrimSpace(strings.ToLower(shell))
	switch s {
	case "", "/sbin/nologin", "/usr/sbin/nologin", "/bin/nologin", "/bin/false", "/usr/bin/false":
		return true
	default:
		return false
	}
}

func stringInSlice(val string, list []string) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func formatPermMode(mode uint32) string {
	return fmt.Sprintf("%03o", mode&0777)
}
