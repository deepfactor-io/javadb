package crawler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/deepfactor-io/javadb/pkg/fileutil"
	"github.com/deepfactor-io/javadb/pkg/types"
	"github.com/google/licenseclassifier/v2/tools/identify_license/backend"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	cmap "github.com/orcaman/concurrent-map/v2"
)

const mavenRepoURL = "https://repo.maven.apache.org/maven2/"
const githubURL = "https://github.com"
const githubRawURL = "https://raw.githubusercontent.com"
const githubBlob = "/blob/"

type Crawler struct {
	dir        string
	licensedir string
	http       *retryablehttp.Client

	rootUrl         string
	wg              sync.WaitGroup
	urlCh           chan string
	limit           *semaphore.Weighted
	wrongSHA1Values []string
	opt             Option

	// license classifier
	classifier *backend.ClassifierBackend

	// uniqueLicenseKeys : key is hash of license url or name in POM, whichever available
	uniqueLicenseKeys cmap.ConcurrentMap[string, License]

	writeToFileChan chan WriteToFile
}

type WriteToFile struct {
	Filepath string
	Data     interface{}
}

type Option struct {
	Limit    int64
	RootUrl  string
	CacheDir string
}

type licenseFilesMeta struct {
	FileName string
	License
}

func NewCrawler(opt Option) Crawler {
	client := retryablehttp.NewClient()
	client.RetryMax = 10
	client.Logger = nil

	if opt.RootUrl == "" {
		opt.RootUrl = mavenRepoURL
	}

	indexDir := filepath.Join(opt.CacheDir, types.IndexesDir)
	log.Printf("Index dir %s", indexDir)

	licensedir := filepath.Join(opt.CacheDir, types.LicenseDir)

	err := os.MkdirAll(licensedir, os.ModePerm)
	if err != nil {
		log.Panicf("panic while creating license cache directory %s .Error:%s", licensedir, err)
	}
	log.Printf("License dir %s", licensedir)

	classifier, err := backend.New()
	if err != nil {
		log.Panicf("panic while creating license classifier backend %s", err)
	}

	return Crawler{
		dir:        indexDir,
		licensedir: licensedir,
		http:       client,

		rootUrl:    opt.RootUrl,
		urlCh:      make(chan string, opt.Limit*10),
		limit:      semaphore.NewWeighted(opt.Limit),
		classifier: classifier,
		opt:        opt,

		uniqueLicenseKeys: cmap.New[License](),

		writeToFileChan: make(chan WriteToFile),
	}
}

func (c *Crawler) Crawl(ctx context.Context) error {
	log.Println("Crawl maven repository and save indexes")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error)
	defer close(errCh)

	// Add a root url
	c.urlCh <- c.rootUrl
	c.wg.Add(1)

	go func() {
		c.wg.Wait()
		close(c.urlCh)
	}()

	crawlDone := make(chan struct{})

	// For the HTTP loop
	go func() {
		defer func() { crawlDone <- struct{}{} }()

		var count int
		for url := range c.urlCh {
			count++
			if count%1000 == 0 {
				log.Printf("Count: %d", count)
			}
			if err := c.limit.Acquire(ctx, 1); err != nil {
				fmt.Println("============== c.limit.Acquire ======================")
				fmt.Println(err)
				fmt.Println("=====================================================")
				errCh <- xerrors.Errorf("semaphore acquire error: %w", err)
				return
			}
			go func(url string) {
				defer c.limit.Release(1)
				defer c.wg.Done()
				if err := c.Visit(ctx, url); err != nil {
					fmt.Println("============== Visit ================================")
					fmt.Println(err)
					fmt.Println("=====================================================")
					errCh <- xerrors.Errorf("visit error: %w", err)
				}
			}(url)
		}
	}()

	go func() {
		for x := range c.writeToFileChan {
			if err := fileutil.WriteJSON(x.Filepath, x.Data); err != nil {
				xerrors.Errorf("json write error: %w", err)
			}
		}
		crawlDone <- struct{}{}
	}()

loop:
	for {
		select {
		// Wait for DB update to complete
		case <-crawlDone:
			break loop
		case err := <-errCh:
			cancel() // Stop all running Visit functions to avoid writing to closed c.urlCh.
			close(c.urlCh)
			return err

		}
	}
	log.Println("Crawl completed")
	if len(c.wrongSHA1Values) > 0 {
		log.Println("Wrong sha1 files:")
		for _, wrongSHA1 := range c.wrongSHA1Values {
			log.Println(wrongSHA1)
		}
	}

	// fetch license information
	return c.classifyLicense(ctx)
}

func (c *Crawler) Visit(ctx context.Context, url string) error {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return xerrors.Errorf("unable to new HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return xerrors.Errorf("http get error (%s): %w", url, err)
	}
	defer resp.Body.Close()

	// There are cases when url doesn't exist
	// e.g. https://repo.maven.apache.org/maven2/io/springboot/ai/spring-ai-anthropic/
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	var children []string
	var foundMetadata bool
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := linkFromSelection(selection)
		if link == "maven-metadata.xml" {
			foundMetadata = true
			return
		} else if link == "../" || !strings.HasSuffix(link, "/") {
			// only `../` and dirs have `/` suffix. We don't need to check other files.
			return
		}
		children = append(children, link)
	})

	if foundMetadata {
		meta, err := c.parseMetadata(ctx, url+"maven-metadata.xml")
		if err != nil {
			return xerrors.Errorf("metadata parse error: %w", err)
		}
		if meta != nil {
			if err = c.crawlSHA1(ctx, url, meta, children); err != nil {
				return err
			}
			// Return here since there is no need to crawl dirs anymore.
			return nil
		}
	}

	c.wg.Add(len(children))

	go func() {
		for _, child := range children {
			select {
			// Context can be canceled if we receive an error from another Visit function.
			case <-ctx.Done():
				return
			default:
				c.urlCh <- url + child
			}
		}
	}()

	return nil
}

func (c *Crawler) crawlSHA1(ctx context.Context, baseURL string, meta *Metadata, dirs []string) error {
	var foundVersions []Version
	// Check each version dir to find links to `*.jar.sha1` files.
	for _, dir := range dirs {
		dirURL := baseURL + dir
		sha1Urls, err := c.sha1Urls(ctx, dirURL)
		if err != nil {
			return xerrors.Errorf("unable to get list of sha1 files from %q: %s", dirURL, err)
		}

		// Remove the `/` suffix to correctly compare file versions with version from directory name.
		dirVersion := strings.TrimSuffix(dir, "/")
		var dirVersionSha1 []byte
		var versions []Version
		var dirVersionPomFetched bool
		var license, dependency string
		for _, sha1Url := range sha1Urls {
			sha1, err := c.fetchSHA1(ctx, sha1Url)
			if err != nil {
				return xerrors.Errorf("unable to fetch sha1: %s", err)
			}
			if ver := versionFromSha1URL(meta.ArtifactID, sha1Url); ver != "" && len(sha1) != 0 {

				// Save sha1 for the file where the version is equal to the version from the directory name in order to remove duplicates later
				// Avoid overwriting dirVersion when inserting versions into the database (sha1 is uniq blob)
				// e.g. `cudf-0.14-cuda10-1.jar.sha1` should not overwrite `cudf-0.14.jar.sha1`
				// https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/
				if ver == dirVersion {
					dirVersionSha1 = sha1
					if !dirVersionPomFetched {
						// fetch license information on the basis of pom url
						pomURL := getPomURL(baseURL, meta.ArtifactID, ver)
						pomValues, err := c.parsePomForLicensesAndDeps(pomURL)
						if err != nil {
							log.Println(err)
						}
						licenseKeys := lo.Uniq(pomValues.Licenses)
						sort.Strings(licenseKeys)

						license = strings.Join(licenseKeys, "|")
						dependency = strings.Join(pomValues.Dependencies, ",")
					}
					dirVersionPomFetched = true
				} else {
					// fetch license information on the basis of pom url
					pomURL := getPomURL(baseURL, meta.ArtifactID, ver)
					pomValues, err := c.parsePomForLicensesAndDeps(pomURL)
					if err != nil {
						log.Println(err)
					}
					licenseKeys := lo.Uniq(pomValues.Licenses)
					sort.Strings(licenseKeys)

					v := Version{
						Version:    ver,
						SHA1:       sha1,
						License:    strings.Join(licenseKeys, "|"),
						Dependency: strings.Join(pomValues.Dependencies, ","),
					}

					versions = append(versions, v)
				}
			}
		}
		// Remove duplicates of dirVersionSha1
		versions = lo.Filter(versions, func(v Version, _ int) bool {
			return !bytes.Equal(v.SHA1, dirVersionSha1)
		})

		if dirVersionSha1 != nil {
			versions = append(versions, Version{
				Version:    dirVersion,
				SHA1:       dirVersionSha1,
				License:    license,
				Dependency: dependency,
			})
		}

		foundVersions = append(foundVersions, versions...)
	}

	if len(foundVersions) == 0 {
		return nil
	}

	index := &Index{
		GroupID:     meta.GroupID,
		ArtifactID:  meta.ArtifactID,
		Versions:    foundVersions,
		ArchiveType: types.JarType,
	}
	fileName := fmt.Sprintf("%s.json", index.ArtifactID)
	filePath := filepath.Join(c.dir, index.GroupID, fileName)
	// if err := fileutil.WriteJSON(filePath, index); err != nil {
	// 	return xerrors.Errorf("json write error: %w", err)
	// }
	printJson := WriteToFile{
		Filepath: filePath,
		Data:     index,
	}
	c.writeToFileChan <- printJson

	return nil
}

func (c *Crawler) sha1Urls(ctx context.Context, url string) ([]string, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to new HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http get error (%s): %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("can't create new goquery doc: %w", err)
	}

	// Version dir may contain multiple `*jar.sha1` files.
	// e.g. https://repo1.maven.org/maven2/org/jasypt/jasypt/1.9.3/
	// We need to take all links.
	var sha1URLs []string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		link := linkFromSelection(selection)
		// Don't include sources, test, javadocs, scaladoc files
		if strings.HasSuffix(link, ".jar.sha1") && !strings.HasSuffix(link, "sources.jar.sha1") &&
			!strings.HasSuffix(link, "test.jar.sha1") && !strings.HasSuffix(link, "tests.jar.sha1") &&
			!strings.HasSuffix(link, "javadoc.jar.sha1") && !strings.HasSuffix(link, "scaladoc.jar.sha1") {
			sha1URLs = append(sha1URLs, url+link)
		}
	})
	return sha1URLs, nil
}

func (c *Crawler) parseMetadata(ctx context.Context, url string) (*Metadata, error) {
	// We need to skip metadata.xml files from groupID folder
	// e.g. https://repo.maven.apache.org/maven2/args4j/maven-metadata.xml
	if len(strings.Split(url, "/")) < 7 {
		return nil, nil
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to new HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http get error (%s): %w", url, err)
	}
	defer resp.Body.Close()

	// There are cases when metadata.xml file doesn't exist
	// e.g. https://repo.maven.apache.org/maven2/io/springboot/ai/spring-ai-vertex-ai-gemini-spring-boot-starter/maven-metadata.xml
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var meta Metadata
	if err = xml.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, xerrors.Errorf("%s decode error: %w", url, err)
	}
	// Skip metadata without `GroupID` and ArtifactID` fields
	// e.g. https://repo.maven.apache.org/maven2/at/molindo/maven-metadata.xml
	if meta.ArtifactID == "" || meta.GroupID == "" {
		return nil, nil
	}

	// we don't need metadata.xml files from version folder
	// e.g. https://repo.maven.apache.org/maven2/HTTPClient/HTTPClient/0.3-3/maven-metadata.xml
	if len(meta.Versioning.Versions) == 0 {
		return nil, nil
	}
	return &meta, nil
}

func (c *Crawler) fetchSHA1(ctx context.Context, url string) ([]byte, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to new HTTP request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http get error (%s): %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// These are cases when version dir contains link to sha1 file
	// But file doesn't exist
	// e.g. https://repo.maven.apache.org/maven2/com/adobe/aem/uber-jar/6.4.8.2/uber-jar-6.4.8.2-sources.jar.sha1
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // TODO add special error for this
	}

	sha1, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("can't read sha1 %s: %w", url, err)
	}

	// there are empty xxx.jar.sha1 files. Skip them.
	// e.g. https://repo.maven.apache.org/maven2/org/wso2/msf4j/msf4j-swagger/2.5.2/msf4j-swagger-2.5.2.jar.sha1
	// https://repo.maven.apache.org/maven2/org/wso2/carbon/analytics/org.wso2.carbon.permissions.rest.api/2.0.248/org.wso2.carbon.permissions.rest.api-2.0.248.jar.sha1
	if len(sha1) == 0 {
		return nil, nil
	}
	// there are xxx.jar.sha1 files with additional data. e.g.:
	// https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	// https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.9.0/xercesImpl-2.9.0.jar.sha1
	var sha1b []byte
	for _, s := range strings.Split(strings.TrimSpace(string(sha1)), " ") {
		sha1b, err = hex.DecodeString(s)
		if err == nil {
			break
		}
	}
	if len(sha1b) == 0 {
		c.wrongSHA1Values = append(c.wrongSHA1Values, fmt.Sprintf("%s (%s)", url, err))
		return nil, nil
	}
	return sha1b, nil
}

func versionFromSha1URL(artifactId, sha1URL string) string {
	ss := strings.Split(sha1URL, "/")
	fileName := ss[len(ss)-1]
	if !strings.HasPrefix(fileName, artifactId) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(fileName, artifactId+"-"), ".jar.sha1")
}

// linkFromSelection returns the link from goquery.Selection.
// There are times when maven breaks `text` - it removes part of the `text` and adds the suffix `...` (`.../` for dirs).
// e.g. `<a href="v1.1.0-226-g847ecff2d8e26f249422247d7665fe15f07b1744/">v1.1.0-226-g847ecff2d8e26f249422247d7665fe15.../</a>`
// In this case we should take `href`.
// But we don't need to get `href` if the text isn't broken.
// To avoid checking unnecessary links.
// e.g. `<pre id="contents"><a href="https://repo.maven.apache.org/maven2/abbot/">../</a>`
func linkFromSelection(selection *goquery.Selection) string {
	link := selection.Text()
	// maven uses `.../` suffix for dirs and `...` suffix for files.
	if href, ok := selection.Attr("href"); ok && (strings.HasSuffix(link, ".../") || (strings.HasSuffix(link, "..."))) {
		link = href
	}
	return link
}

func (c *Crawler) parsePomForLicensesAndDeps(url string) (PomParsedValues, error) {
	var pomParsedValues PomParsedValues
	pomXml, err := c.parseAndSubstitutePom(url)
	if err != nil {
		return pomParsedValues, xerrors.Errorf("can't parse pom xml from %s: %w", url, err)
	}

	if len(pomXml.Licenses) == 0 && len(pomXml.Dependencies) == 0 {
		return pomParsedValues, nil
	}

	for _, l := range pomXml.Licenses {
		l.LicenseKey = getLicenseKey(l)

		// update uniqueLicenseKeys map
		c.uniqueLicenseKeys.Set(l.LicenseKey, l)

		pomParsedValues.Licenses = append(pomParsedValues.Licenses, l.LicenseKey)
	}

	pomParsedValues.Dependencies = pomXml.Dependencies

	return pomParsedValues, nil

}

func (c *Crawler) classifyLicense(ctx context.Context) error {
	normalizedLicenseMap := make(map[string]string)

	// prepare classifier data i.e create temporary files with license text to be used for classification
	licenseFiles, err := c.prepareClassifierData(ctx)
	if err != nil {
		return err
	}

	files := make([]string, 0)
	filesLicenseMap := make(map[string]License)

	// change license file list to map
	for _, data := range licenseFiles {
		if _, ok := filesLicenseMap[data.FileName]; !ok {
			filesLicenseMap[data.FileName] = data.License
			files = append(files, data.FileName)
		}
	}

	if len(filesLicenseMap) == 0 {
		return nil
	}

	// classify licenses

	// 1 minute is the timeout for license classification of a file
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// c.opt.Limit is the number of concurrent tasks spawned to process license files
	errs := c.classifier.ClassifyLicensesWithContext(ctx, int(c.opt.Limit), files, true)
	if len(errs) > 0 {
		log.Println("errors in license classification ", errs)
	}

	// extract results
	results := c.classifier.GetResults()
	sort.Sort(results)

	// process results to update the normalizedLicenseMap
	if results.Len() > 0 {
		for _, r := range results {
			if licenseVal, ok := filesLicenseMap[r.Filename]; ok {
				// skip non license detection results
				if r.MatchType != "License" {
					continue
				}

				// since results are sorted, we can skip processing of data with confidence <90%
				if r.Confidence < 0.9 {
					break
				}

				// skip processing since a higher confidence result is already processed
				if licenseVal.ClassificationConfidence > r.Confidence {
					// since there are multiple matches available with confidence > 90% , fallback to license name if available
					// else pick highest confidence match
					if len(licenseVal.Name) > 0 {
						// rest license key so that it fallsback to name
						delete(normalizedLicenseMap, licenseVal.LicenseKey)
					}
					continue
				}

				licenseVal.ClassificationConfidence = r.Confidence
				filesLicenseMap[r.Filename] = licenseVal

				// update normalized license map
				normalizedLicenseMap[licenseVal.LicenseKey] = r.Name
			}
		}
	}

	defer func() {
		// update normalized license map for license keys which couldn't be classified or had no url in pom for classification
		uniqLicenseKeys := c.uniqueLicenseKeys.Items()
		for key, license := range uniqLicenseKeys {
			if _, ok := normalizedLicenseMap[key]; !ok {
				if len(license.Name) > 0 {
					normalizedLicenseMap[key] = license.Name
				}
			}
		}

		// err := fileutil.WriteJSON(c.licensedir+types.NormalizedlicenseFileName, normalizedLicenseMap)
		// if err != nil {
		// 	log.Println(err)
		// }
		printJson := WriteToFile{
			Filepath: c.licensedir + types.NormalizedlicenseFileName,
			Data:     normalizedLicenseMap,
		}
		c.writeToFileChan <- printJson
	}()

	return nil
}

func (c *Crawler) prepareClassifierData(ctx context.Context) ([]licenseFilesMeta, error) {
	log.Println("Preparing license classifier data")

	var licenseFiles []licenseFilesMeta

	// switch from concurrent to normal map
	uniqLicenseKeyMap := c.uniqueLicenseKeys.Items()
	uniqueLicenseKeyList := c.uniqueLicenseKeys.Keys()

	client := http.Client{
		Timeout: 10 * time.Second,
	}

	licenseKeyChannel := make(chan string, len(uniqueLicenseKeyList))

	log.Printf("Total license keys to be processed %d", len(uniqueLicenseKeyList))

	// dump license keys to the channel so that they can be processed
	for _, key := range uniqueLicenseKeyList {
		licenseKeyChannel <- key
	}

	limit := semaphore.NewWeighted(c.opt.Limit)

	// error channel
	errCh := make(chan error)
	defer close(errCh)

	// status channel to track processing of license keys
	type status struct {
		Meta licenseFilesMeta
		Done bool
	}
	prepStatus := make(chan status, len(uniqueLicenseKeyList))
	defer close(prepStatus)

	// process license keys channel
	go func() {
		for licenseKey := range licenseKeyChannel {

			if err := limit.Acquire(ctx, 1); err != nil {
				errCh <- xerrors.Errorf("semaphore acquire error: %w", err)
			}

			// process license key to generate license file
			go func(licenseKey string) {
				defer limit.Release(1)

				licenseFileName := getLicenseFileName(c.licensedir, licenseKey)
				licenseMeta := uniqLicenseKeyMap[licenseKey]
				ok, err := c.generateLicenseFile(client, licenseFileName, licenseMeta)
				if err != nil {
					errCh <- xerrors.Errorf("generateLicenseFile error: %w", err)
				}

				// update status post processing of license key
				prepStatus <- status{
					Done: ok,
					Meta: licenseFilesMeta{
						License:  licenseMeta,
						FileName: licenseFileName,
					},
				}
			}(licenseKey)
		}
	}()

	count := 0
loop:
	for {
		select {
		case status := <-prepStatus:
			count++
			if status.Done {
				licenseFiles = append(licenseFiles, status.Meta)
			}

			if count%1000 == 0 {
				log.Printf("Processed %d license keys", count)
			}

			if count == len(uniqueLicenseKeyList) {
				close(licenseKeyChannel)
				break loop
			}
		case err := <-errCh:
			close(licenseKeyChannel)
			return licenseFiles, err

		}
	}

	log.Println("Preparation of license classifier data completed")

	return licenseFiles, nil

}

func (c *Crawler) generateLicenseFile(client http.Client, licenseFileName string, licenseMeta License) (bool, error) {

	// if url not available then no point using the license classifier
	// Names can be analyzed but in most cases license classifier does not result in any matches
	if !strings.HasPrefix(licenseMeta.URL, "http") {
		return false, nil
	}

	// create file
	f, err := os.Create(licenseFileName)
	if err != nil {
		return false, err
	}

	defer f.Close()

	// normalize github urls so that raw content is downloaded
	// Eg. https://github.com/dom4j/dom4j/blob/master/LICENSE -> https://raw.githubusercontent.com/dom4j/dom4j/master/LICENSE

	// TODO: Check if we need to use a github url parser library for the same
	if strings.HasPrefix(licenseMeta.URL, githubURL) {
		// remove blob from url
		licenseMeta.URL = strings.Replace(licenseMeta.URL, githubBlob, "/", 1)

		// raw url
		licenseMeta.URL = strings.TrimPrefix(licenseMeta.URL, githubURL)
		licenseMeta.URL = githubRawURL + licenseMeta.URL

	}

	// download license url contents
	resp, err := client.Get(licenseMeta.URL)
	if resp == nil {
		return false, nil
	}

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return false, nil
	}

	return true, nil
}
