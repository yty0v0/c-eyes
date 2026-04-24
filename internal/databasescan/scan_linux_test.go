//go:build linux

package databasescan

import "testing"

func TestDetectLinuxDBPostgres(t *testing.T) {
	tests := []struct {
		name    string
		proc    string
		cmdline []string
		want    string
	}{
		{
			name:    "postgres process name",
			proc:    "postgres",
			cmdline: []string{"/usr/lib/postgresql/15/bin/postgres", "-D", "/var/lib/postgresql/data"},
			want:    "PostgreSQL",
		},
		{
			name:    "postmaster process name",
			proc:    "postmaster",
			cmdline: []string{"postmaster", "-D", "/var/lib/postgresql/data"},
			want:    "PostgreSQL",
		},
		{
			name:    "non postgres",
			proc:    "python",
			cmdline: []string{"python", "app.py"},
			want:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectLinuxDB(tc.proc, tc.cmdline)
			if got != tc.want {
				t.Fatalf("detectLinuxDB(%q, %v)=%q, want %q", tc.proc, tc.cmdline, got, tc.want)
			}
		})
	}
}

func TestApplyLinuxSpecialFieldsPostgresDataDir(t *testing.T) {
	rec := &DatabaseRecord{Name: strPtr("PostgreSQL")}
	proc := linuxProcInfo{
		Name:    "postgres",
		Cmdline: []string{"/opt/metasploit-framework/embedded/bin/postgres", "-D", "/home/msf/.msf4/db", "-p", "5433"},
	}

	applyLinuxSpecialFields(rec, "PostgreSQL", proc)
	if rec.DataDir == nil || *rec.DataDir != "/home/msf/.msf4/db" {
		t.Fatalf("expected dataDir /home/msf/.msf4/db, got %+v", rec.DataDir)
	}
}

func TestBuildDockerProxyRecordPostgres(t *testing.T) {
	proc := linuxProcInfo{
		Name: "docker-proxy",
		Cmdline: []string{
			"docker-proxy", "-proto", "tcp",
			"-host-ip", "0.0.0.0",
			"-host-port", "5433",
			"-container-ip", "172.17.0.3",
			"-container-port", "5432",
		},
		User: "root",
	}
	socket := linuxSocketRow{
		Proto:  "tcp",
		BindIP: "0.0.0.0",
		Port:   5433,
	}

	rec, ok := buildDockerProxyRecord(proc, socket)
	if !ok {
		t.Fatalf("expected docker-proxy postgres record")
	}
	if rec.Name == nil || *rec.Name != "PostgreSQL" {
		t.Fatalf("expected Name=PostgreSQL, got %+v", rec.Name)
	}
	if rec.Port == nil || *rec.Port != 5433 {
		t.Fatalf("expected Port=5433, got %+v", rec.Port)
	}
	if rec.DBName == nil || *rec.DBName != "172.17.0.3:5432" {
		t.Fatalf("expected DBName=172.17.0.3:5432, got %+v", rec.DBName)
	}
}

func TestBuildDockerProxyRecordMongo(t *testing.T) {
	proc := linuxProcInfo{
		Name: "docker-proxy",
		Cmdline: []string{
			"docker-proxy", "-proto", "tcp",
			"-host-ip", "0.0.0.0",
			"-host-port", "27017",
			"-container-ip", "172.17.0.2",
			"-container-port", "27017",
		},
		User: "root",
	}
	socket := linuxSocketRow{
		Proto:  "tcp",
		BindIP: "0.0.0.0",
		Port:   27017,
	}

	rec, ok := buildDockerProxyRecord(proc, socket)
	if !ok {
		t.Fatalf("expected docker-proxy mongodb record")
	}
	if rec.Name == nil || *rec.Name != "MongoDB" {
		t.Fatalf("expected Name=MongoDB, got %+v", rec.Name)
	}
	if rec.Port == nil || *rec.Port != 27017 {
		t.Fatalf("expected Port=27017, got %+v", rec.Port)
	}
	if rec.DBName == nil || *rec.DBName != "172.17.0.2:27017" {
		t.Fatalf("expected DBName=172.17.0.2:27017, got %+v", rec.DBName)
	}
}

func TestBuildDockerProxySocket(t *testing.T) {
	proc := linuxProcInfo{
		Name: "docker-proxy",
		Cmdline: []string{
			"docker-proxy", "-proto", "tcp",
			"-host-ip", "0.0.0.0",
			"-host-port", "5433",
			"-container-ip", "172.17.0.3",
			"-container-port", "5432",
		},
	}
	socket, ok := buildDockerProxySocket(proc)
	if !ok {
		t.Fatalf("expected docker proxy socket parsed")
	}
	if socket.Proto != "tcp" {
		t.Fatalf("expected proto tcp, got %q", socket.Proto)
	}
	if socket.BindIP != "0.0.0.0" {
		t.Fatalf("expected bind ip 0.0.0.0, got %q", socket.BindIP)
	}
	if socket.Port != 5433 {
		t.Fatalf("expected port 5433, got %d", socket.Port)
	}
}
