package pom

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"

	"github.com/deepfactor-io/go-dep-parser/pkg/log"
)

var (
	centralURL = "https://repo.maven.apache.org/maven2/"
	pomCache   = NewPOMCache()
)

type Parser struct {
	httpClient         *retryablehttp.Client
	cache              *PomCache
	remoteRepositories map[string]struct{}
}

func NewParser(client *retryablehttp.Client) *Parser {
	remoteRepos := make(map[string]struct{}, 0)
	remoteRepos[centralURL] = struct{}{}

	return &Parser{
		httpClient:         client,
		cache:              pomCache,
		remoteRepositories: remoteRepos,
	}
}

func (p *Parser) Parse(url string) (*pomXML, []artifact, error) {
	var content *pomXML
	var err error

	// check if the pom url is present in url cache
	if cachedResult := p.cache.getPomXML(url); cachedResult != nil {
		content = cachedResult
	} else {
		content, err = p.parseAndSubstitutePom(url)
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to parse POM: %w", err)
		}

		p.cache.putPomXML(url, content)
	}

	root := &pom{content: content}
	result, err := p.analyze(root, analysisOptions{})
	if err != nil {
		return nil, nil, xerrors.Errorf("analyze error: %w", err)
	}

	return content, result.dependencies, nil

}

func (p *Parser) resolve(art artifact, rootDepManagement []pomDependency) (analysisResult, error) {
	// If the artifact is found in cache, it is returned.
	if cachedResult := p.cache.get(art); cachedResult != nil {
		return *cachedResult, nil
	}

	log.Logger.Debugf("Resolving %s:%s:%s...", art.GroupID, art.ArtifactID, art.Version)
	pomContent, err := p.tryRepository(art.GroupID, art.ArtifactID, art.Version.String())
	if err != nil {
		log.Logger.Debug(err)
	}
	result, err := p.analyze(pomContent, analysisOptions{
		exclusions:    art.Exclusions,
		depManagement: rootDepManagement,
	})
	if err != nil {
		return analysisResult{}, xerrors.Errorf("analyze error: %w", err)
	}

	return result, nil
}

type analysisResult struct {
	filePath             string
	artifact             artifact
	dependencies         []artifact
	dependencyManagement []pomDependency // Keep the order of dependencies in 'dependencyManagement'
	properties           map[string]string
	// modules              []string
}

type analysisOptions struct {
	exclusions    map[string]struct{}
	depManagement []pomDependency // from the root POM
}

func (p *Parser) analyze(pom *pom, opts analysisOptions) (analysisResult, error) {
	if pom == nil || pom.content == nil {
		return analysisResult{}, nil
	}

	// If the artifact is found in cache, it is returned.
	if cachedResult := p.cache.get(pom.artifact()); cachedResult != nil {
		return *cachedResult, nil
	}

	// Update remoteRepositories
	for _, remoteRepo := range pom.repositories() {
		if _, ok := p.remoteRepositories[remoteRepo]; !ok {
			p.remoteRepositories[remoteRepo] = struct{}{}
		}
	}

	// Parent
	parent, err := p.parseParent(pom.content.Parent)
	if err != nil {
		return analysisResult{}, xerrors.Errorf("parent error: %w", err)
	}

	// Inherit values/properties from parent
	pom.inherit(parent)

	// Generate properties
	props := pom.properties()

	// dependencyManagements have the next priority:
	// 1. Managed dependencies from this POM
	// 2. Managed dependencies from parent of this POM
	depManagement := p.mergeDependencyManagements(pom.content.DependencyManagement.Dependencies.Dependency, parent.dependencyManagement)

	// Merge dependencies. Child dependencies must be preferred than parent dependencies.
	// Parents don't have to resolve dependencies.
	deps := p.parseDependencies(pom.content.Dependencies.Dependency, props, depManagement, opts.depManagement, opts.exclusions)
	deps = p.mergeDependencies(parent.dependencies, deps, opts.exclusions)

	result := analysisResult{
		filePath:             pom.filePath,
		artifact:             pom.artifact(),
		dependencies:         deps,
		dependencyManagement: depManagement,
		properties:           props,
		// modules:              pom.content.Modules.Module,
	}

	p.cache.put(pom.artifact(), result)

	return result, nil
}

func (p *Parser) mergeDependencyManagements(depManagements ...[]pomDependency) []pomDependency {
	uniq := map[string]struct{}{}
	var depManagement []pomDependency
	// The preceding argument takes precedence.
	for _, dm := range depManagements {
		for _, dep := range dm {
			if _, ok := uniq[dep.Name()]; ok {
				continue
			}
			depManagement = append(depManagement, dep)
			uniq[dep.Name()] = struct{}{}
		}
	}
	return depManagement
}

func (p *Parser) parseDependencies(deps []pomDependency, props map[string]string, depManagement, rootDepManagement []pomDependency,
	exclusions map[string]struct{}) []artifact {
	// Imported POMs often have no dependencies, so dependencyManagement resolution can be skipped.
	if len(deps) == 0 {
		return nil
	}

	// Resolve dependencyManagement
	depManagement = p.resolveDepManagement(props, depManagement)

	var dependencies []artifact
	for _, d := range deps {
		// Resolve dependencies
		d = d.Resolve(props, depManagement, rootDepManagement)

		if (d.Scope != "" && d.Scope != "compile") || d.Optional {
			continue
		}
		dependencies = append(dependencies, d.ToArtifact(exclusions))
	}
	return dependencies
}

func (p *Parser) resolveDepManagement(props map[string]string, depManagement []pomDependency) []pomDependency {
	var newDepManagement, imports []pomDependency
	for _, dep := range depManagement {
		// cf. https://howtodoinjava.com/maven/maven-dependency-scopes/#import
		if dep.Scope == "import" {
			imports = append(imports, dep)
		} else {
			// Evaluate variables
			newDepManagement = append(newDepManagement, dep.Resolve(props, nil, nil))
		}
	}

	// Managed dependencies with a scope of "import" should be processed after other managed dependencies.
	// cf. https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#importing-dependencies
	for _, imp := range imports {
		art := newArtifact(imp.GroupID, imp.ArtifactID, imp.Version, nil, props)
		result, err := p.resolve(art, nil)
		if err != nil {
			continue
		}
		for k, dd := range result.dependencyManagement {
			// Evaluate variables and overwrite dependencyManagement
			result.dependencyManagement[k] = dd.Resolve(result.properties, nil, nil)
		}
		newDepManagement = p.mergeDependencyManagements(newDepManagement, result.dependencyManagement)
	}
	return newDepManagement
}

func (p *Parser) mergeDependencies(parent, child []artifact, exclusions map[string]struct{}) []artifact {
	var deps []artifact
	unique := map[string]struct{}{}

	for _, d := range append(parent, child...) {
		if excludeDep(exclusions, d) {
			continue
		}
		if _, ok := unique[d.Name()]; ok {
			continue
		}
		unique[d.Name()] = struct{}{}
		deps = append(deps, d)
	}

	return deps
}

func excludeDep(exclusions map[string]struct{}, art artifact) bool {
	if _, ok := exclusions[art.Name()]; ok {
		return true
	}
	// Maven can use "*" in GroupID and ArtifactID fields to exclude dependencies
	// https://maven.apache.org/pom.html#exclusions
	for exlusion := range exclusions {
		// exclusion format - "<groupID>:<artifactID>"
		e := strings.Split(exlusion, ":")
		if (e[0] == art.GroupID || e[0] == "*") && (e[1] == art.ArtifactID || e[1] == "*") {
			return true
		}
	}
	return false
}

func (p *Parser) parseParent(parent pomParent) (analysisResult, error) {
	// Pass nil properties so that variables in <parent> are not evaluated.
	target := newArtifact(parent.GroupId, parent.ArtifactId, parent.Version, nil, nil)
	// if version is property (e.g. ${revision}) - we still need to parse this pom
	if target.IsEmpty() && !isProperty(parent.Version) {
		return analysisResult{}, nil
	}

	// If the artifact is found in cache, it is returned.
	if cachedResult := p.cache.get(target); cachedResult != nil {
		return *cachedResult, nil
	}

	parentPOM, err := p.retrieveParent(target)
	if err != nil {
		log.Logger.Debugf("parent POM not found: %s", err)
	}

	result, err := p.analyze(parentPOM, analysisOptions{})
	if err != nil {
		return analysisResult{}, xerrors.Errorf("analyze error: %w", err)
	}

	return result, nil
}

func (p *Parser) retrieveParent(target artifact) (*pom, error) {
	var errs error

	// If not found, search local/remote remoteRepositories
	pom, err := p.tryRepository(target.GroupID, target.ArtifactID, target.Version.String())
	if err != nil {
		return nil, multierror.Append(errs, err)
	}

	return pom, nil
}

func (p *Parser) tryRepository(groupID, artifactID, version string) (*pom, error) {
	// Generate a proper path to the pom.xml
	// e.g. com.fasterxml.jackson.core, jackson-annotations, 2.10.0
	//      => com/fasterxml/jackson/core/jackson-annotations/2.10.0/jackson-annotations-2.10.0.pom
	paths := strings.Split(groupID, ".")
	paths = append(paths, artifactID, version)
	paths = append(paths, fmt.Sprintf("%s-%s.pom", artifactID, version))

	// Search remote remoteRepositories
	loaded, err := p.fetchPOMFromRemoteRepository(paths)
	if err == nil {
		return loaded, nil
	}

	return nil, xerrors.Errorf("%s:%s:%s was not found in local/remote repositories", groupID, artifactID, version)
}

func (p *Parser) fetchPOMFromRemoteRepository(paths []string) (*pom, error) {
	var content *pomXML

	// try all remoteRepositories
	for repo := range p.remoteRepositories {
		repoURL, err := url.Parse(repo)
		if err != nil {
			continue
		}

		paths = append([]string{repoURL.Path}, paths...)
		repoURL.Path = path.Join(paths...)

		// check the url is present in the cache
		if cachedResult := p.cache.getPomXML(repoURL.String()); cachedResult != nil {
			return &pom{
				filePath: "", // from remote repositories
				content:  cachedResult,
			}, nil
		}

		resp, err := p.httpClient.Get(repoURL.String())
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		defer resp.Body.Close()

		content, err = parsePom(resp.Body)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse the remote POM: %w", err)
		}

		p.cache.putPomXML(repoURL.String(), content)

		return &pom{
			filePath: "", // from remote repositories
			content:  content,
		}, nil
	}

	return nil, xerrors.Errorf("the POM was not found in remote remoteRepositories")
}

func parsePom(r io.Reader) (*pomXML, error) {
	parsed := &pomXML{}
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(parsed); err != nil {
		return nil, xerrors.Errorf("xml decode error: %w", err)
	}
	return parsed, nil
}

func (p *Parser) parseAndSubstitutePom(url string) (*pomXML, error) {
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return nil, xerrors.Errorf("can't get pom xml from %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("error reading response body from %s: %w", url, err)
	}

	xmlData, err := preprocessXML(string(body))
	if err != nil {
		return nil, xerrors.Errorf("error preprocessing xml from %s: %w", url, err)
	}

	pom, err := parsePom(strings.NewReader(xmlData))
	if err != nil {
		return nil, xerrors.Errorf("error parsing pom from %s: %w", url, err)
	}

	return pom, nil
}

func preprocessXML(xmlData string) (string, error) {
	// Remove all hr tags
	xmlData = strings.ReplaceAll(xmlData, "<hr>", "")
	xmlData = strings.ReplaceAll(xmlData, "</hr>", "")
	return xmlData, nil
}
