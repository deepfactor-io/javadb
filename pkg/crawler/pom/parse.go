package pom

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"

	"github.com/deepfactor-io/go-dep-parser/pkg/log"
)

const (
	centralURL = "https://repo.maven.apache.org/maven2/"
)

type Parser struct {
	cache              *pomCache
	remoteRepositories []string
}

func NewParser() *Parser {
	remoteRepos := []string{centralURL}
	return &Parser{
		cache:              newPOMCache(),
		remoteRepositories: remoteRepos,
	}
}

func (p *Parser) Parse(r ReadSeekerAt) (*pomXML, []Dependency, error) {
	content, err := parsePom(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to parse POM: %w", err)
	}

	root := &pom{
		content: content,
	}

	result, err := p.analyze(root, analysisOptions{})
	if err != nil {
		return nil, nil, xerrors.Errorf("analyze error: %w", err)
	}

	// Cache root POM
	p.cache.put(result.artifact, result)

	_, deps, _ := p.parseRoot(root.artifact())
	return content, deps, nil

}

func (p *Parser) parseRoot(root artifact) ([]Library, []Dependency, error) {

	// Prepare a queue for dependencies
	queue := newArtifactQueue()

	// Enqueue root POM
	root.Root = true
	root.Module = false
	queue.enqueue(root)

	var (
		libs              []Library
		deps              []Dependency
		rootDepManagement []pomDependency
		uniqArtifacts     = map[string]artifact{}
		uniqDeps          = map[string][]string{}
	)

	// Iterate direct and transitive dependencies
	for !queue.IsEmpty() {
		art := queue.dequeue()

		// Modules should be handled separately so that they can have independent dependencies.
		// It means multi-module allows for duplicate dependencies.
		if art.Module {
			moduleLibs, moduleDeps, err := p.parseRoot(art)
			if err != nil {
				return nil, nil, err
			}
			libs = append(libs, moduleLibs...)
			if moduleDeps != nil {
				deps = append(deps, moduleDeps...)
			}
			continue
		}

		// For soft requirements, skip dependency resolution that has already been resolved.
		if uniqueArt, ok := uniqArtifacts[art.Name()]; ok {
			if !uniqueArt.Version.shouldOverride(art.Version) {
				continue
			}
			// mark artifact as Direct, if saved artifact is Direct
			// take a look `hard requirement for the specified version` test
			if uniqueArt.Direct {
				art.Direct = true
			}
		}

		result, err := p.resolve(art, rootDepManagement)
		if err != nil {
			return nil, nil, xerrors.Errorf("resolve error (%s): %w", art, err)
		}

		if art.Root {
			// Managed dependencies in the root POM affect transitive dependencies
			rootDepManagement = p.resolveDepManagement(result.properties, result.dependencyManagement)

			// mark root artifact and its dependencies as Direct
			art.Direct = true
			result.dependencies = lo.Map(result.dependencies, func(dep artifact, _ int) artifact {
				dep.Direct = true
				return dep
			})
		}

		// Resolve transitive dependencies later
		queue.enqueue(result.dependencies...)

		// Offline mode may be missing some fields.
		if !art.IsEmpty() {
			// Override the version
			uniqArtifacts[art.Name()] = artifact{
				Version: art.Version,
				// Licenses: result.artifact.Licenses,
				Direct: art.Direct,
			}

			// save only dependency names
			// version will be determined later
			dependsOn := lo.Map(result.dependencies, func(a artifact, _ int) string {
				return a.Name()
			})
			uniqDeps[packageID(art.Name(), art.Version.String())] = dependsOn
		}
	}

	// Convert to []types.Library and []types.Dependency
	for name, art := range uniqArtifacts {
		lib := Library{
			ID:      packageID(name, art.Version.String()),
			Name:    name,
			Version: art.Version.String(),
			// License:  art.JoinLicenses(),
			Indirect: !art.Direct,
		}
		libs = append(libs, lib)

		// Convert dependency names into dependency IDs
		dependsOn := lo.FilterMap(uniqDeps[lib.ID], func(dependOnName string, _ int) (string, bool) {
			ver := depVersion(dependOnName, uniqArtifacts)
			return packageID(dependOnName, ver), ver != ""
		})

		sort.Strings(dependsOn)
		if len(dependsOn) > 0 {
			deps = append(deps, Dependency{
				ID:        lib.ID,
				DependsOn: dependsOn,
			})
		}
	}

	sort.Sort(Libraries(libs))
	sort.Sort(Dependencies(deps))

	return libs, deps, nil
}

// depVersion finds dependency in uniqArtifacts and return its version
func depVersion(depName string, uniqArtifacts map[string]artifact) string {
	if art, ok := uniqArtifacts[depName]; ok {
		return art.Version.String()
	}
	return ""
}

func (p *Parser) resolve(art artifact, rootDepManagement []pomDependency) (analysisResult, error) {
	// If the artifact is found in cache, it is returned.
	if result := p.cache.get(art); result != nil {
		return *result, nil
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

	p.cache.put(art, result)
	return result, nil
}

type analysisResult struct {
	filePath             string
	artifact             artifact
	dependencies         []artifact
	dependencyManagement []pomDependency // Keep the order of dependencies in 'dependencyManagement'
	properties           map[string]string
	modules              []string
}

type analysisOptions struct {
	exclusions    map[string]struct{}
	depManagement []pomDependency // from the root POM
}

func (p *Parser) analyze(pom *pom, opts analysisOptions) (analysisResult, error) {
	if pom == nil || pom.content == nil {
		return analysisResult{}, nil
	}

	// Update remoteRepositories
	p.remoteRepositories = UniqueStrings(append(p.remoteRepositories, pom.repositories()...))
	// Parent
	parent, err := p.parseParent(pom.filePath, pom.content.Parent)
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

	return analysisResult{
		filePath:             pom.filePath,
		artifact:             pom.artifact(),
		dependencies:         deps,
		dependencyManagement: depManagement,
		properties:           props,
		// modules:              pom.content.Modules.Module,
	}, nil
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

func (p *Parser) parseParent(currentPath string, parent pomParent) (analysisResult, error) {
	// Pass nil properties so that variables in <parent> are not evaluated.
	target := newArtifact(parent.GroupId, parent.ArtifactId, parent.Version, nil, nil)
	// if version is property (e.g. ${revision}) - we still need to parse this pom
	if target.IsEmpty() && !isProperty(parent.Version) {
		return analysisResult{}, nil
	}
	log.Logger.Debugf("Start parent: %s", target.String())
	defer func() {
		log.Logger.Debugf("Exit parent: %s", target.String())
	}()

	// If the artifact is found in cache, it is returned.
	if result := p.cache.get(target); result != nil {
		return *result, nil
	}

	parentPOM, err := p.retrieveParent(currentPath, parent.RelativePath, target)
	if err != nil {
		log.Logger.Debugf("parent POM not found: %s", err)
	}

	result, err := p.analyze(parentPOM, analysisOptions{})
	if err != nil {
		return analysisResult{}, xerrors.Errorf("analyze error: %w", err)
	}

	// p.cache.put(target, result)

	return result, nil
}

func (p *Parser) retrieveParent(currentPath, relativePath string, target artifact) (*pom, error) {
	var errs error

	// If not found, search local/remote remoteRepositories
	pom, err := p.tryRepository(target.GroupID, target.ArtifactID, target.Version.String())
	if err != nil {
		errs = multierror.Append(errs, err)
	} else {
		return pom, nil
	}

	// Reaching here means the POM wasn't found
	return nil, errs
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
	// try all remoteRepositories
	for _, repo := range p.remoteRepositories {
		repoURL, err := url.Parse(repo)
		if err != nil {
			continue
		}

		paths = append([]string{repoURL.Path}, paths...)
		repoURL.Path = path.Join(paths...)

		resp, err := http.Get(repoURL.String())
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		content, err := parsePom(resp.Body)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse the remote POM: %w", err)
		}

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
