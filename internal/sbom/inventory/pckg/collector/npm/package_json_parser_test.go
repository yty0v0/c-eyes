// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package npm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"edrsystem/internal/sbom/inventory/pckg/collector"
	"edrsystem/internal/sbom/model"
)

func TestGetFromLicenseField(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "case-string-single",
			args: args{[]byte(`"MIT"`)},
			want: []string{"MIT"},
		},
		{
			name: "case-string-multiple",
			args: args{[]byte(`"MIT OR Apache-2.0"`)},
			want: []string{"MIT", "Apache-2.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := getFromLicenseField(tt.args.b)
			fmt.Println(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getFromLicenseField() got = %v, want %v", got, tt.want)
			}
		})
	}
}

type args struct {
	path string
}

var packageJSONTests = []struct {
	name    string
	args    args
	want    []model.Package
	want1   []model.Relationship
	wantErr bool
}{
	{
		name: "case-package-license-string",
		args: args{path: "test_material/package/package-license-string.json"},
		want: []model.Package{
			*newPackage("wj-demo2", "1.1.3", "test_material/package/package-license-string.json"),
			*newPackage("wj-demo4", "1.1.3", "test_material/package/package-license-string.json"),
			*newPackage("wj-demo5", "", "test_material/package/package-license-string.json"),
			*newPackage("wj-demo6", "", "test_material/package/package-license-string.json"),
			*newPackage("wj-demo7", "", "test_material/package/package-license-string.json"),
			*newPackage("ant-design-vue", "3.0.0-alpha.9", "test_material/package/package-license-string.json"),
			*newPackage("wj-demo9", "", "test_material/package/package-license-string.json"),
			*newPackage("wj-demo10", "", "test_material/package/package-license-string.json"),
			func() model.Package {
				p := newPackage("wj-demo3", "8.8.2", "test_material/package/package-license-string.json")
				p.Dependencies = []string{"pkg:npm/wj-demo2@1.1.3",
					"pkg:npm/wj-demo4@1.1.3",
					"pkg:npm/wj-demo5",
					"pkg:npm/wj-demo6",
					"pkg:npm/wj-demo7",
					"pkg:npm/ant-design-vue@3.0.0-alpha.9",
					"pkg:npm/wj-demo9",
					"pkg:npm/wj-demo10",
				}
				p.LicenseDeclared = []string{"MIT"}
				return *p
			}(),
		},
		want1:   nil,
		wantErr: false,
	}, {
		name: "case-package-license-object",
		args: args{path: "test_material/package/package-license-object.json"},
		want: []model.Package{
			*newPackage("wj-demo2", "1.1.3", "test_material/package/package-license-object.json"),
			func() model.Package {
				p := newPackage("wj-demo3", "8.8.2", "test_material/package/package-license-object.json")
				p.Dependencies = []string{"pkg:npm/wj-demo2@1.1.3"}
				p.LicenseDeclared = []string{"MIT"}
				return *p
			}(),
		},
		want1:   nil,
		wantErr: false,
	}, {
		name: "case-package-license-array",
		args: args{path: "test_material/package/package-licenses-array.json"},
		want: []model.Package{
			*newPackage("wj-demo2", "1.1.3", "test_material/package/package-licenses-array.json"),
			func() model.Package {
				p := newPackage("wj-demo3", "8.8.2", "test_material/package/package-licenses-array.json")
				p.Dependencies = []string{"pkg:npm/wj-demo2@1.1.3"}
				p.LicenseDeclared = []string{"MIT", "Apache-2.0"}
				return *p
			}(),
		},
		want1:   nil,
		wantErr: false,
	},
}

func TestPackageJsonParserParse(t *testing.T) {
	for _, tt := range packageJSONTests {
		t.Run(tt.name, func(t *testing.T) {
			pa := PackageJSONParser{}
			got, err := pa.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, collector.SortPackage(tt.want)) {
				t.Errorf("Collect() got = %v, \nwant %v", got, tt.want)
			}
		})
	}
}

func BenchmarkPackageJsonParser(b *testing.B) {
	for _, tt := range packageJSONTests {
		pa := PackageJSONParser{}
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = pa.Parse(tt.args.path)
			}
		})
	}
}

func TestPackageJsonParserParseWithUTF8BOM(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "package.json")
	content := "\uFEFF{\"name\":\"bom-demo\",\"version\":\"1.0.0\",\"dependencies\":{\"axios\":\"^1.7.7\"}}"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp package.json failed: %v", err)
	}

	pa := PackageJSONParser{}
	got, err := pa.Parse(path)
	if err != nil {
		t.Fatalf("parse package.json with BOM failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d: %#v", len(got), got)
	}

	pkgMap := make(map[string]model.Package)
	for _, pkg := range got {
		pkgMap[pkg.Name] = pkg
	}
	mainPkg, ok := pkgMap["bom-demo"]
	if !ok {
		t.Fatalf("missing main package bom-demo in result: %#v", got)
	}
	if mainPkg.Version != "1.0.0" {
		t.Fatalf("unexpected main package version: %s", mainPkg.Version)
	}
	if len(mainPkg.Dependencies) != 1 || mainPkg.Dependencies[0] != "pkg:npm/axios@1.7.7" {
		t.Fatalf("unexpected main package dependencies: %#v", mainPkg.Dependencies)
	}
	depPkg, ok := pkgMap["axios"]
	if !ok {
		t.Fatalf("missing dependency package axios in result: %#v", got)
	}
	if depPkg.Version != "1.7.7" {
		t.Fatalf("unexpected axios version: %s", depPkg.Version)
	}
}
