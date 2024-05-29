package crawler

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	pom "github.com/deepfactor-io/javadb/pkg/crawler/pom"
	"golang.org/x/xerrors"
)

type PomParsedValues struct {
	Licenses     []string
	Dependencies []string
}

type PomProject struct {
	GroupID      string `xml:"groupId"`
	ArtifactID   string `xml:"artifactId"`
	Version      string `xml:"version"`
	Name         string `xml:"name"`
	Description  string `xml:"description"`
	URL          string `xml:"url"`
	Licenses     []License
	Dependencies []string
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
	Text       string `xml:",chardata"`
	Scope      string `xml:"scope"`
	Optional   bool   `xml:"optional"`
}

func preprocessXML(xmlData string) (string, error) {
	// Remove all hr tags
	xmlData = strings.ReplaceAll(xmlData, "<hr>", "")
	xmlData = strings.ReplaceAll(xmlData, "</hr>", "")
	return xmlData, nil
}

func (c *Crawler) parseAndSubstitutePom(url string) (PomProject, error) {
	var project PomProject

	x := time.Now()
	resp, err := c.httpClient.Get(url)
	if err != nil {
		fmt.Println("check this error -----")
		fmt.Println(err)
	}
	fmt.Println("completed in = ", time.Since(x).Minutes())

	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return project, nil
	}
	if err != nil {
		return project, xerrors.Errorf("can't get pom xml from %s: %w", url, err)
	}
	defer resp.Body.Close()

	rr, err := pom.NewReadSeekerAt(resp.Body)
	if err != nil {
		return project, xerrors.Errorf("reader error: %w", err)
	}

	pomXML, deps, err := c.parser.Parse(rr)
	if err != nil {
		return project, xerrors.Errorf("cant parse pom %s: %w", url, err)
	}

	project.GroupID = pomXML.GroupId
	project.ArtifactID = pomXML.ArtifactId
	project.Version = pomXML.Version
	if len(deps) == 1 {
		project.Dependencies = deps[0].DependsOn
	}

	for _, v := range pomXML.Licenses.License {
		project.Licenses = append(project.Licenses, License{
			Name:                     v.Name,
			URL:                      v.URL,
			LicenseKey:               v.LicenseKey,
			ClassificationConfidence: v.ClassificationConfidence,
		})
	}

	return project, nil
}
