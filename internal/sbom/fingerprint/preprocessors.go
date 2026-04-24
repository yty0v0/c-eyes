
// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package fingerprint

import (
	"strings"

	"edrsystem/internal/sbom/fingerprint/preprocessor"
	"edrsystem/internal/sbom/fingerprint/preprocessor/cpp"
	"edrsystem/internal/sbom/fingerprint/preprocessor/csharp"
	"edrsystem/internal/sbom/fingerprint/preprocessor/dart"
	"edrsystem/internal/sbom/fingerprint/preprocessor/golang"
	"edrsystem/internal/sbom/fingerprint/preprocessor/java"
	"edrsystem/internal/sbom/fingerprint/preprocessor/javascript"
	"edrsystem/internal/sbom/fingerprint/preprocessor/lua"
	"edrsystem/internal/sbom/fingerprint/preprocessor/objectivec"
	"edrsystem/internal/sbom/fingerprint/preprocessor/php"
	"edrsystem/internal/sbom/fingerprint/preprocessor/python"
	"edrsystem/internal/sbom/fingerprint/preprocessor/ruby"
	"edrsystem/internal/sbom/fingerprint/preprocessor/rust"
	"edrsystem/internal/sbom/fingerprint/preprocessor/swift"
	"edrsystem/internal/sbom/util"

	"golang.org/x/exp/slices"
)

func AllPreProcessors() []preprocessor.PreProcessor {
	return []preprocessor.PreProcessor{
		cpp.NewCppPreprocessor(),
		csharp.NewCSharpPreprocessor(),
		golang.NewGolangPreprocessor(),
		java.NewJavaPreprocessor(),
		javascript.NewJavascriptPreprocess(),
		php.NewPhpPreprocessor(),
		python.NewPythonPreprocessor(),
		ruby.NewRubyPreprocessor(),
		rust.NewRustPreprocessor(),
		swift.NewSwiftPreprocessor(),
		lua.NewLuaPreprocessor(),
		objectivec.NewObjectivecPreprocessor(),
		dart.NewDartPreprocessor(),
	}
}

func GetPreProcessors(languages string) []preprocessor.PreProcessor {
	allPreProcessors := AllPreProcessors()
	languages = strings.TrimSpace(languages)
	if languages == "" || languages == "*" {
		return allPreProcessors
	}
	languagesArr := strings.Split(languages, ",")
	languagesArr = util.SliceMap(languagesArr, func(lang string) string {
		return strings.TrimSpace(lang)
	})
	languagesArr = util.SliceFilter(languagesArr, func(name string) bool {
		return name != ""
	})
	return util.SliceFilter(allPreProcessors, func(processor preprocessor.PreProcessor) bool {
		return slices.Contains(languagesArr, processor.Name())
	})
}

