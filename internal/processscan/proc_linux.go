//go:build linux

package processscan

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type procStat struct {
	Comm       string
	State      string
	PPID       int
	TTY        string
	StartTicks uint64
}

type procStatus struct {
	Name  string
	UID   *int64
	GID   *int64
	Uname *string
	Gname *string
	Root  *bool
	TTY   *string
}

func parseProcStat(data string) (procStat, error) {
	start := strings.Index(data, "(")
	end := strings.LastIndex(data, ")")
	if start == -1 || end == -1 || end <= start {
		return procStat{}, errors.New("stat format too short")
	}
	comm := data[start+1 : end]
	rest := strings.Fields(strings.TrimSpace(data[end+1:]))
	if len(rest) < 20 {
		return procStat{}, errors.New("stat format too short")
	}

	state := rest[0]
	ppid, _ := strconv.Atoi(rest[1])
	ttyNr := rest[4]
	startTicks, _ := strconv.ParseUint(rest[19], 10, 64)

	return procStat{
		Comm:       comm,
		State:      state,
		PPID:       ppid,
		TTY:        ttyNr,
		StartTicks: startTicks,
	}, nil
}

func parseProcStatus(data string) procStatus {
	status := procStatus{}
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:\t") {
			status.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:\t"))
		}
		if strings.HasPrefix(line, "Uid:\t") {
			parts := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
			if len(parts) > 0 {
				if uid, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
					status.UID = int64Ptr(uid)
					root := uid == 0
					status.Root = boolPtr(root)
					if name := lookupUserName(uid); name != nil {
						status.Uname = name
					}
				}
			}
		}
		if strings.HasPrefix(line, "Gid:\t") {
			parts := strings.Fields(strings.TrimPrefix(line, "Gid:\t"))
			if len(parts) > 0 {
				if gid, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
					status.GID = int64Ptr(gid)
					if name := lookupGroupName(gid); name != nil {
						status.Gname = name
					}
				}
			}
		}
	}

	if status.Uname == nil && status.UID != nil {
		if name := lookupUserName(*status.UID); name != nil {
			status.Uname = name
		}
	}
	if status.Gname == nil && status.GID != nil {
		if name := lookupGroupName(*status.GID); name != nil {
			status.Gname = name
		}
	}

	return status
}

func parseCmdline(data []byte) string {
	parts := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == 0
	})
	return strings.Join(parts, " ")
}

var bootTimeOnce sync.Once
var bootTime time.Time
var bootTimeErr error

func getBootTime() (time.Time, error) {
	bootTimeOnce.Do(func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			bootTimeErr = err
			return
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "btime ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if sec, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						bootTime = time.Unix(sec, 0)
						return
					}
				}
			}
		}
		bootTimeErr = errors.New("btime not found")
	})

	return bootTime, bootTimeErr
}

var hzOnce sync.Once
var hz float64 = 100

func getClockTicks() float64 {
	hzOnce.Do(func() {
		if estimate := estimateClockTicks(); estimate > 0 {
			hz = estimate
		}
	})
	return hz
}

func estimateClockTicks() float64 {
	uptime, err := readUptime()
	if err != nil || uptime <= 0 {
		return 0
	}
	total, err := readTotalJiffies()
	if err != nil || total <= 0 {
		return 0
	}
	return total / uptime
}

func readUptime() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, errors.New("uptime format invalid")
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func readTotalJiffies() (float64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return 0, errors.New("cpu stat format too short")
			}
			var total float64
			for _, part := range parts[1:] {
				val, err := strconv.ParseFloat(part, 64)
				if err != nil {
					continue
				}
				total += val
			}
			return total, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("cpu stat not found")
}

var passwdOnce sync.Once
var passwdByID map[int64]string
var groupOnce sync.Once
var groupByID map[int64]string

func lookupUserName(uid int64) *string {
	loadPasswd()
	if name, ok := passwdByID[uid]; ok {
		return strPtr(name)
	}
	return nil
}

func lookupGroupName(gid int64) *string {
	loadGroup()
	if name, ok := groupByID[gid]; ok {
		return strPtr(name)
	}
	return nil
}

func loadPasswd() {
	passwdOnce.Do(func() {
		passwdByID = make(map[int64]string)
		file, err := os.Open("/etc/passwd")
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) < 3 {
				continue
			}
			uid, err := strconv.ParseInt(parts[2], 10, 64)
			if err != nil {
				continue
			}
			passwdByID[uid] = parts[0]
		}
	})
}

func loadGroup() {
	groupOnce.Do(func() {
		groupByID = make(map[int64]string)
		file, err := os.Open("/etc/group")
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) < 3 {
				continue
			}
			gid, err := strconv.ParseInt(parts[2], 10, 64)
			if err != nil {
				continue
			}
			groupByID[gid] = parts[0]
		}
	})
}

func readTTY(pid int) *string {
	link, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", "0"))
	if err != nil {
		return nil
	}
	if strings.HasPrefix(link, "/dev/") {
		return strPtr(link)
	}
	return nil
}
