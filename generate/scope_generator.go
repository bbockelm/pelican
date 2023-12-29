package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"

	"gopkg.in/yaml.v3"
)

type ScopeName struct {
	Raw     string
	Display string
}

var requiredScopeKeys = [3]string{"description", "issuedBy", "acceptedBy"}

func handleCaseConversion(s string) string {
	var camelCase string
	nextCap := false

	for _, r := range s {
		if r == '_' || r == '.' {
			nextCap = true
			if r == '.' {
				camelCase += "."
			}
			continue
		}

		if nextCap {
			camelCase += string(unicode.ToUpper(r))
			nextCap = false
		} else {

			camelCase += string(r)
		}
	}

	return camelCase
}

func GenTokenScope() {
	filename, _ := filepath.Abs("../docs/scopes.yaml")
	yamlFile, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer yamlFile.Close()

	decoder := yaml.NewDecoder(yamlFile)

	var values []interface{}

	for {
		var value map[string]interface{}
		if err := decoder.Decode(&value); err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Errorf("document decode failed: %w", err))
		}
		values = append(values, value)
	}

	scopes := make([]ScopeName, 0)

	for i := 0; i < len(values); i++ {
		entry := values[i].(map[string]interface{})

		scopeName, ok := entry["name"].(string)
		if !ok {
			panic(fmt.Sprintf("Scope entry at position %d is missing the name attribute", i))
		}
		for _, keyName := range requiredScopeKeys {
			if _, ok := entry[keyName]; !ok {
				panic(fmt.Sprintf("Parameter entry '%s' is missing required key '%s'",
					scopeName, keyName))
			}
		}
		camelScopeName := handleCaseConversion(scopeName)
		scopeNameInSnake := strings.Replace(camelScopeName, ".", "_", 1)
		r := []rune(scopeNameInSnake)
		r[0] = unicode.ToUpper(r[0])
		displayName := string(r)
		scopes = append(scopes, ScopeName{Raw: scopeName, Display: displayName})
	}

	// Create the file to be generated
	f, err := os.Create("../utils/token_scopes.go")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	err = tokenTemplate.Execute(f, struct {
		Scopes []ScopeName
	}{Scopes: scopes})

	if err != nil {
		panic(err)
	}
}

var tokenTemplate = template.Must(template.New("").Parse(`// Code generated by go generate; DO NOT EDIT.

package utils

type TokenScope string

const (
	{{range $idx, $scope := .Scopes}}
	{{$scope.Display}} TokenScope = "{{$scope.Raw}}"
	{{- end}}
)

func (s TokenScope) String() string {
	return string(s)
}
`))
