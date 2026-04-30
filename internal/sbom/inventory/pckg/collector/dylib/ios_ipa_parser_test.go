
// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package dylib

import (
	"testing"

	"edrsystem/internal/sbom/inventory/pckg/collector"
	"edrsystem/internal/sbom/model"
	"edrsystem/internal/sbom/util"
)

func TestIPAParser_Parse(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		wantLen int
		wantPkg model.Package
		wantErr bool
	}{
		{
			"case-ipa-1",
			args{path: "test_material/app.ipa"},
			28,
			newPackage("UIKit", "6441.1.101", ""),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewIPAParser()
			got, err := parser.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Fatalf("Parse() got %d packages, want %d", len(got), tt.wantLen)
			}
			if !util.SliceAny(got, func(p model.Package) bool {
				return model.PackageEqual(&p, &tt.wantPkg)
			}) {
				t.Errorf("Parse() missing expected package %+v", tt.wantPkg)
			}
		})
	}
}

func TestParseDylibLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want model.Package
	}{
		{
			name: "@rpath",
			line: "@rpath/libswift_Concurrency.dylib (5.7.2)",
			want: newPackage("libswift_Concurrency", "5.7.2", ""),
		}, {
			name: "usr_lib",
			line: "/usr/lib/libobjc.A.dylib (228.0)",
			want: newPackage("libobjc.A", "228.0", ""),
		}, {
			name: "System_Library_Frameworks",
			line: "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation (1949.0)",
			want: newPackage("CoreFoundation", "1949.0", ""),
		},
	}
	for i := 0; i < len(tests); i++ {
		test := tests[i]
		t.Run(test.name, func(tt *testing.T) {
			pkg := parseDylibLine(test.line, "")
			if !collector.EqualPackage(pkg, &test.want) {
				tt.Errorf("not equal, got = %v , \n want = %v", pkg, test.want)
			}
		})
	}
}

