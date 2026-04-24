
// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package mvn

import (
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"

	"edrsystem/internal/sbom/util"
)

var propertyMatcher = regexp.MustCompile("[$][{][^}]+[}]")

func parsePomXMLProject(path string, reader io.Reader) (*PomProject, error) {
	project, err := decodePomXML(reader)
	if err != nil {
		return nil, err
	}
	return newPomProject(path, project), nil
}

func decodePomXML(content io.Reader) (project gopom.Project, err error) {
	decoder := xml.NewDecoder(content)
	// prevent against warnings for "xml: encoding "iso-8859-1" declared but Decoder.CharsetReader is nil"
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&project); err != nil {
		return project, fmt.Errorf("unable to unmarshal pom.xml: %w", err)
	}

	return project, nil
}

func newPomProject(path string, p gopom.Project) *PomProject {
	licenseInfos := make([]string, 0)
	if p.Licenses != nil {
		for _, lic := range *p.Licenses {
			if lic.Name != nil {
				licenseInfos = append(licenseInfos, *lic.Name)
			}
		}
	}
	dependencies := make([]PomDependency, 0)
	if p.Dependencies != nil {
		dependencies = util.SliceMap(*p.Dependencies, func(dep gopom.Dependency) PomDependency {
			return PomDependency{
				GroupID:    stringValue(dep.GroupID),
				ArtifactID: stringValue(dep.ArtifactID),
				Version:    stringValue(dep.Version),
			}
		})
	}
	pomProject := &PomProject{
		Path:         path,
		Parent:       pomParent(p, p.Parent),
		GroupID:      resolveProperty(p, p.GroupID),
		ArtifactID:   stringValue(p.ArtifactID),
		Version:      resolveProperty(p, p.Version),
		Name:         stringValue(p.Name),
		Description:  cleanDescription(stringValue(p.Description)),
		URL:          stringValue(p.URL),
		Licenses:     licenseInfos,
		Dependencies: dependencies,
	}

	return pomProject
}

func cleanDescription(original string) (cleaned string) {
	descriptionLines := strings.Split(original, "\n")
	for _, line := range descriptionLines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		cleaned += line + " "
	}
	return strings.TrimSpace(cleaned)
}

func pomParent(pom gopom.Project, parent *gopom.Parent) (result *PomParent) {
	if parent == nil {
		return nil
	}
	if stringValue(parent.ArtifactID) != "" || stringValue(parent.GroupID) != "" || stringValue(parent.Version) != "" {
		result = &PomParent{
			GroupID:    resolveProperty(pom, parent.GroupID),
			ArtifactID: stringValue(parent.ArtifactID),
			Version:    resolveProperty(pom, parent.Version),
		}
	}
	return result
}

// resolveProperty emulates some maven property resolution logic by looking in the project's variables
// as well as supporting the project expressions like ${project.parent.groupId}.
// If no match is found, the entire expression including ${} is returned
func resolveProperty(pom gopom.Project, property *string) string {
	if property == nil {
		return ""
	}
	if *property == "" {
		return ""
	}
	return propertyMatcher.ReplaceAllStringFunc(*property, func(match string) string {
		propertyName := strings.TrimSpace(match[2 : len(match)-1])
		if pom.Properties != nil {
			if value, ok := pom.Properties.Entries[propertyName]; ok {
				return value
			}
		}
		// if we don't find anything directly in the pom properties,
		// see if we have a project.x expression and process this based
		// on the xml tags in gopom
		parts := strings.Split(propertyName, ".")
		numParts := len(parts)
		if numParts > 1 && strings.TrimSpace(parts[0]) == "project" {
			pomValue := reflect.ValueOf(pom)
			pomValueType := pomValue.Type()
			for partNum := 1; partNum < numParts; partNum++ {
				if pomValueType.Kind() == reflect.Pointer {
					if pomValue.IsNil() {
						return ""
					}
					pomValue = pomValue.Elem()
					pomValueType = pomValue.Type()
				}
				if pomValueType.Kind() != reflect.Struct {
					break
				}
				part := parts[partNum]
				for fieldNum := 0; fieldNum < pomValueType.NumField(); fieldNum++ {
					f := pomValueType.Field(fieldNum)
					tag := strings.Split(f.Tag.Get("xml"), ",")[0]
					if part == tag {
						pomValue = pomValue.Field(fieldNum)
						pomValueType = pomValue.Type()
						if partNum == numParts-1 {
							if pomValueType.Kind() == reflect.Pointer {
								if pomValue.IsNil() {
									return ""
								}
								pomValue = pomValue.Elem()
							}
							return fmt.Sprintf("%v", pomValue.Interface())
						}
						break
					}
				}
			}
		}
		return match
	})
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

