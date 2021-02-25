package lib

import (
	"embed"
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
)

type Poc struct {
	Name   string              `yaml:"name"`
	Set    map[string]string   `yaml:"set"`
	Sets   map[string][]string `yaml:"sets"`
	Rules  []Rules             `yaml:"rules"`
	Detail Detail              `yaml:"detail"`
}

type Rules struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Search          string            `yaml:"search"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Expression      string            `yaml:"expression"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
}

func LoadMultiPoc(Pocs embed.FS, pocname string) []*Poc {
	var pocs []*Poc
	for _, f := range SelectPoc(Pocs, pocname) {
		if p, err := loadPoc(f, Pocs); err == nil {
			pocs = append(pocs, p)
		}
	}
	return pocs
}

func loadPoc(fileName string, Pocs embed.FS) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := Pocs.ReadFile("pocs/" + fileName)

	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		return nil, err
	}
	return p, err
}

func SelectPoc(Pocs embed.FS, pocname string) []string {
	entries, err := Pocs.ReadDir("pocs")
	if err != nil {
		fmt.Println(err)
	}
	var foundFiles []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), pocname) {
			foundFiles = append(foundFiles, entry.Name())
		}
	}
	return foundFiles
}
