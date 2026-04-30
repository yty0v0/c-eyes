
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

func TestCollector_Collect(t *testing.T) {
	tests := []struct {
		name    string
		files   []collector.File
		wantLen int
		wantPkg model.Package
		wantErr bool
	}{
		{
			name:    "ipa-1",
			files:   []collector.File{collector.NewFileMeta("test_material/app.ipa")},
			wantLen: 28,
			wantPkg: newPackage("UIKit", "6441.1.101", ""),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewCollector()
			for i := range tt.files {
				g.TryToAccept(tt.files[i])
			}
			got, err := g.Collect()
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLen {
				t.Fatalf("Collect() got %d packages, want %d", len(got), tt.wantLen)
			}
			if !util.SliceAny(got, func(p model.Package) bool {
				return model.PackageEqual(&p, &tt.wantPkg)
			}) {
				t.Errorf("Collect() missing expected package %+v", tt.wantPkg)
			}
		})
	}
}

