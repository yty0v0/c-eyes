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
	"fmt"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"

	"edrsystem/internal/sbom/util"
)

// FileMatcher is a file parser, check whether a file matches a rule
type FileMatcher interface {
	Match(file File) bool
	Description() string
}

// FileNameMatcher match a file by file name
type FileNameMatcher struct {
	Names []string
}

func (f *FileNameMatcher) Match(file File) bool {
	return util.SliceContains(f.Names, file.FileName())
}

func (f *FileNameMatcher) Description() string {
	return fmt.Sprintf("filename: %s", strings.Join(f.Names, ","))
}

// FilePatternMatcher match a file by file pattern
type FilePatternMatcher struct {
	// the pattern ref https://pkg.go.dev/path/filepath#Match
	Patterns []string
}

func hasPathSeparator(value string) bool {
	return strings.Contains(value, "/") || strings.Contains(value, `\`)
}

func normalizeToSlash(value string) string {
	return strings.ReplaceAll(value, `\`, "/")
}

func (f *FilePatternMatcher) Match(file File) bool {
	return util.SliceAny(f.Patterns, func(p string) bool {
		path := file.FileName()
		if hasPathSeparator(p) {
			path = file.FullName()
		}
		normalizedPattern := normalizeToSlash(filepath.Clean(p))
		normalizedPath := normalizeToSlash(filepath.Clean(path))
		matched, err := pathpkg.Match(normalizedPattern, normalizedPath)
		return err == nil && matched
	})
}

func (f *FilePatternMatcher) Description() string {
	return fmt.Sprintf("pattern: %s", strings.Join(f.Patterns, ","))
}

// FileRegexpMatcher match a file by regexp
type FileRegexpMatcher struct {
	Regexps []*regexp.Regexp
}

func (f *FileRegexpMatcher) Match(file File) bool {
	return util.SliceAny(f.Regexps, func(reg *regexp.Regexp) bool {
		if reg == nil {
			return false
		}
		path := file.FileName()
		if hasPathSeparator(reg.String()) {
			path = file.FullName()
		}
		normalizedPath := normalizeToSlash(filepath.Clean(path))
		return reg.MatchString(path) || reg.MatchString(normalizedPath)
	})
}

func (f *FileRegexpMatcher) Description() string {
	regexps := util.SliceMap(f.Regexps, func(reg *regexp.Regexp) string {
		return reg.String()
	})
	return fmt.Sprintf("regexps: %s", strings.Join(regexps, ","))
}

// FileMimeMatcher match a file by file mime
type FileMimeMatcher struct {
	Mimes []string
}

func (f *FileMimeMatcher) Match(file File) bool {
	return util.SliceContains(f.Mimes, file.Mime())
}

func (f *FileMimeMatcher) Description() string {
	return fmt.Sprintf("filemime: %s", strings.Join(f.Mimes, ","))
}
