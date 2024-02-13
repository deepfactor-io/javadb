package crawler

import (
	"encoding/xml"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"
)

type PomParsedValues struct {
	Licenses     []string
	Dependencies []Dependency
}

type PomProject struct {
	GroupID      string       `xml:"groupId"`
	ArtifactID   string       `xml:"artifactId"`
	Version      string       `xml:"version"`
	Name         string       `xml:"name"`
	Description  string       `xml:"description"`
	URL          string       `xml:"url"`
	Licenses     []License    `xml:"licenses>license"`
	Dependencies []Dependency `xml:"dependencies>dependency"`
	Properties   Properties   `xml:"properties"`
}

type Properties struct {
	Variables map[string]string `xml:",any"`
}

func (p *Properties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Variables = make(map[string]string)
	for {
		var e xml.Token
		e, err := d.Token()
		if err != nil {
			return err
		}

		switch elem := e.(type) {
		case xml.StartElement:
			key := strings.TrimPrefix(elem.Name.Local, "property.")
			var value string
			if err := d.DecodeElement(&value, &elem); err != nil {
				return err
			}
			p.Variables[key] = value
		case xml.EndElement:
			if elem == start.End() {
				return nil
			}
		}
	}
}

func substitutePlaceholders(project *PomProject) {
	for key, value := range project.Properties.Variables {
		placeholder := "${" + key + "}"
		// Substitute placeholders in dependencies
		for i := range project.Dependencies {
			project.Dependencies[i].GroupID = strings.ReplaceAll(project.Dependencies[i].GroupID, placeholder, value)
			project.Dependencies[i].ArtifactID = strings.ReplaceAll(project.Dependencies[i].ArtifactID, placeholder, value)
			project.Dependencies[i].Version = strings.ReplaceAll(project.Dependencies[i].Version, placeholder, value)
		}
	}
}

type License struct {
	Name                     string `xml:"name"`
	URL                      string `xml:"url"`
	LicenseKey               string
	ClassificationConfidence float64
}

type Dependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

func preprocessXML(xmlData string) (string, error) {
	// Add closing tags to unclosed <hr> tags
	xmlData = strings.ReplaceAll(xmlData, "<hr>", "")
	xmlData = strings.ReplaceAll(xmlData, "</hr>", "")
	return xmlData, nil
}

func parseAndSubstitutePom(url string) (PomProject, error) {
	var project PomProject

	resp, err := http.Get(url)
	if resp.StatusCode == http.StatusNotFound {
		return project, nil
	}
	if err != nil {
		return project, xerrors.Errorf("can't get pom xml from %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return project, xerrors.Errorf("error reading response body from %s: %w", url, err)
	}

	xmlData, err := preprocessXML(string(body))
	if err != nil {
		return project, xerrors.Errorf("error preprocessing xml from %s: %w", url, err)
	}

	decoder := xml.NewDecoder(strings.NewReader(xmlData))
	decoder.CharsetReader = charset.NewReaderLabel
	err = decoder.Decode(&project)
	if err != nil {
		return project, xerrors.Errorf("error decoding pom.xml from %s: %w", url, err)
	}

	substitutePlaceholders(&project)

	return project, nil
}
