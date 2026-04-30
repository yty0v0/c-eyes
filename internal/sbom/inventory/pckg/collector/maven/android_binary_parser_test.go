
// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package maven

import (
	"testing"

	"edrsystem/internal/sbom/model"
	"edrsystem/internal/sbom/util"
)

func TestAPKParser_Parse(t *testing.T) {
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
			"case-apk-1",
			args{path: "test_material/android/app.apk"},
			45,
			*newPackage("androidx.compose.material3", "material3", "1.0.0", ""),
			false,
		},
		{
			"case-aab-1",
			args{path: "test_material/android/app.aab"},
			45,
			*newPackage("androidx.compose.material3", "material3", "1.0.0", ""),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewAndroidBinaryParser()
			got, err := parser.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
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

