package websitescan

import "testing"

func TestParseTomcatUsesConnectorSecurityAttributes(t *testing.T) {
	content := `<Server><Service>
<Connector port="8080" protocol="AJP/1.3"/>
<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true" secure="true" scheme="https"/>
<Host name="tomcat.example.com" appBase="/opt/tomcat/webapps"/>
</Service></Server>`

	webRoot, domains, port, proto := parseTomcat(content)
	if webRoot != "/opt/tomcat/webapps" {
		t.Fatalf("unexpected webRoot: %q", webRoot)
	}
	if len(domains) != 1 || domains[0].Name == nil || *domains[0].Name != "tomcat.example.com" {
		t.Fatalf("unexpected domains: %+v", domains)
	}
	if port == nil || *port != 8443 {
		t.Fatalf("unexpected port: %+v", port)
	}
	if proto != "https" {
		t.Fatalf("unexpected proto: %q", proto)
	}
}

func TestParseTomcatFallsBackToCommonHTTPSPorts(t *testing.T) {
	content := `<Server><Service><Connector port="9443" protocol="HTTP/1.1"/><Host name="tomcat.example.com" appBase="/opt/tomcat/webapps"/></Service></Server>`

	_, _, port, proto := parseTomcat(content)
	if port == nil || *port != 9443 {
		t.Fatalf("unexpected port: %+v", port)
	}
	if proto != "https" {
		t.Fatalf("unexpected proto: %q", proto)
	}
}

func TestParseTomcatDefaultsHTTPWhenNoSignals(t *testing.T) {
	content := `<Server><Service><Connector port="8080" protocol="HTTP/1.1"/><Host name="tomcat.example.com" appBase="/opt/tomcat/webapps"/></Service></Server>`

	_, _, port, proto := parseTomcat(content)
	if port == nil || *port != 8080 {
		t.Fatalf("unexpected port: %+v", port)
	}
	if proto != "http" {
		t.Fatalf("unexpected proto: %q", proto)
	}
}

func TestParseTomcatPrefersHTTPSConnectorWhenBothHTTPAndHTTPSPresent(t *testing.T) {
	content := `<Server><Service>
<Connector port="8080" protocol="HTTP/1.1"/>
<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"/>
<Host name="tomcat.example.com" appBase="/opt/tomcat/webapps"/>
</Service></Server>`

	_, _, port, proto := parseTomcat(content)
	if port == nil || *port != 8443 {
		t.Fatalf("unexpected port: %+v", port)
	}
	if proto != "https" {
		t.Fatalf("unexpected proto: %q", proto)
	}
}

func TestParseTomcatUsesSchemeSignalOnCustomPort(t *testing.T) {
	content := `<Server><Service><Connector port="10443" protocol="HTTP/1.1" scheme="https" secure="false"/><Host name="tomcat.example.com" appBase="/opt/tomcat/webapps"/></Service></Server>`

	_, _, port, proto := parseTomcat(content)
	if port == nil || *port != 10443 {
		t.Fatalf("unexpected port: %+v", port)
	}
	if proto != "https" {
		t.Fatalf("unexpected proto: %q", proto)
	}
}
