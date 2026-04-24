// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package collector

import (
	"bytes"
	"strings"
)

var utf8BOMBytes = []byte{0xEF, 0xBB, 0xBF}

const utf8BOMString = "\uFEFF"

// TrimUTF8BOMBytes removes an optional UTF-8 BOM prefix from raw bytes.
func TrimUTF8BOMBytes(data []byte) []byte {
	return bytes.TrimPrefix(data, utf8BOMBytes)
}

// TrimUTF8BOMString removes an optional UTF-8 BOM rune from string content.
func TrimUTF8BOMString(value string) string {
	return strings.TrimPrefix(value, utf8BOMString)
}
