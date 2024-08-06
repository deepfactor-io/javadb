package crawler_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/deepfactor-io/javadb/pkg/crawler"
	"github.com/google/licenseclassifier/v2/tools/identify_license/backend"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
)

func TestCrawl(t *testing.T) {
	tests := []struct {
		name                        string
		fileNames                   map[string]string
		goldenPath                  string
		goldenNormalizedlicensePath string
		filePath                    string
		normalizedLicensePath       string
	}{
		{
			name: "happy path",
			fileNames: map[string]string{
				"/maven2/":                               "testdata/index.html",
				"/maven2/abbot/":                         "testdata/abbot.html",
				"/maven2/abbot/abbot/":                   "testdata/abbot_abbot.html",
				"/maven2/abbot/abbot/maven-metadata.xml": "testdata/maven-metadata.xml",
				"/maven2/abbot/abbot/0.12.3/abbot-0.12.3.jar.sha1": "testdata/abbot-0.12.3.jar.sha1",
				"/maven2/abbot/abbot/0.12.3/abbot-0.12.3.pom":      "testdata/abbot-0.12.3.pom",
				"/maven2/abbot/abbot/0.13.0/abbot-0.13.0.jar.sha1": "testdata/abbot-0.13.0.jar.sha1",
				"/maven2/abbot/abbot/0.13.0/abbot-0.13.0.pom":      "testdata/abbot-0.13.0.pom",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1":   "testdata/abbot-1.4.0.jar.sha1",
				"/maven2/abbot/abbot/1.4.0/abbot-1.4.0.pom":        "testdata/abbot-1.4.0.pom",
			},
			goldenPath:                  "testdata/golden/abbot/abbot.json",
			goldenNormalizedlicensePath: "testdata/golden/abbot/normalized_license.json",

			filePath:              "indexes/abbot/abbot.json",
			normalizedLicensePath: "licenses/normalized_license.json",
		},
		{
			name: "test path",
			fileNames: map[string]string{
				"/maven2/":                              "testdata/hibernate-core/index.html",
				"/maven2/org/hibernate/hibernate-core/": "testdata/hibernate-core/org_hibernate_hibernate-core.html",
				"/maven2/org/hibernate/hibernate-core/maven-metadata.xml":                                      "testdata/hibernate-core/maven-metadata.xml",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/":                                            "testdata/hibernate-core/hibernate-core_5.4.9.Final.html",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final-javadoc.jar":      "testdata/hibernate-core/hibernate-core-5.4.9.Final-javadoc.jar",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final-javadoc.jar.asc":  "testdata/hibernate-core/hibernate-core-5.4.9.Final-javadoc.jar.asc",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final-javadoc.jar.md5":  "testdata/hibernate-core/hibernate-core-5.4.9.Final-javadoc.jar.md5",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final-javadoc.jar.sha1": "testdata/hibernate-core/hibernate-core-5.4.9.Final-javadoc.jar.sha1",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final-sources.jar":      "testdata/hibernate-core/hibernate-core-5.4.9.Final-sources.jar",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final-sources.jar.asc":  "testdata/hibernate-core/hibernate-core-5.4.9.Final-sources.jar.asc",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final-sources.jar.md5":  "testdata/hibernate-core/hibernate-core-5.4.9.Final-sources.jar.md5",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final-sources.jar.sha1": "testdata/hibernate-core/hibernate-core-5.4.9.Final-sources.jar.sha1",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final.jar":              "testdata/hibernate-core/hibernate-core-5.4.9.Final.jar",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final.jar.asc":          "testdata/hibernate-core/hibernate-core-5.4.9.Final.jar.asc",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final.jar.md5":          "testdata/hibernate-core/hibernate-core-5.4.9.Final.jar.md5",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final.jar.sha1":         "testdata/hibernate-core/hibernate-core-5.4.9.Final.jar.sha1",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final.pom":              "testdata/hibernate-core/hibernate-core-5.4.9.Final.pom",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final.pom.asc":          "testdata/hibernate-core/hibernate-core-5.4.9.Final.pom.asc",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final.pom.md5":          "testdata/hibernate-core/hibernate-core-5.4.9.Final.pom.md5",
				"/maven2/org/hibernate/hibernate-core/5.4.9.Final/hibernate-core-5.4.9.Final.pom.sha1":         "testdata/hibernate-core/hibernate-core-5.4.9.Final.pom.sha1",
			},
			goldenPath:                  "testdata/golden/hibernate-core/hibernate-core.json",
			goldenNormalizedlicensePath: "testdata/golden/hibernate-core/normalized_license.json",

			filePath:              "indexes/org.hibernate/hibernate-core.json",
			normalizedLicensePath: "licenses/normalized_license.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fileName, ok := tt.fileNames[r.URL.Path]
				if !ok {
					t.Log("Error! URL not found: ", r.URL.Path)
					http.NotFound(w, r)
					return
				}

				t.Logf("Serving file %s at path %s", fileName, r.URL.Path)
				http.ServeFile(w, r, fileName)
			}))
			defer ts.Close()

			t.Log("Running http server at URL: ", ts.URL)

			tmpDir := t.TempDir()
			cl := crawler.NewCrawler(crawler.Option{
				RootUrl:  ts.URL + "/maven2/",
				Limit:    1,
				CacheDir: tmpDir,
			})

			err := cl.Crawl(context.Background())
			assert.NoError(t, err)

			got, err := os.ReadFile(filepath.Join(tmpDir, tt.filePath))
			assert.NoError(t, err)

			want, err := os.ReadFile(tt.goldenPath)
			assert.NoError(t, err)

			assert.JSONEq(t, string(want), string(got))

			// normalized license json file check
			got, err = os.ReadFile(filepath.Join(tmpDir, tt.normalizedLicensePath))
			assert.NoError(t, err)

			want, err = os.ReadFile(tt.goldenNormalizedlicensePath)
			assert.NoError(t, err)

			assert.JSONEq(t, string(want), string(got))
		})
	}
}

func TestLicenseClassifier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	classifier, err := backend.New()
	if err != nil {
		return
	}

	fileNames := []string{
		// "/home/hrithikyadav/Desktop/TestCrawltest_path2948945980/001/licenses/trivy_license_4044415468.txt",
		// "/tmp/trivy_license_4044415468.txt",
	}

	// c.opt.Limit is the number of concurrent tasks spawned to process license files
	errs := classifier.ClassifyLicensesWithContext(ctx, 1, fileNames, true)
	if len(errs) > 0 {
		log.Println("errors in license classification ", errs)
	}

	// extract results
	results := classifier.GetResults()
	sort.Sort(results)

	t.Log("Classifier results array Len: ", len(results))
	for _, r := range results {
		t.Log("License Name: ", r.Name)
	}
}

func TestGenerateLicenseFile(t *testing.T) {
	licenseFileName := "test_generate_license.txt"
	defer func() {
		if _, err := os.Stat(licenseFileName); err == nil {
			// remove the test file
			os.Remove(licenseFileName)
		}
	}()

	client := retryablehttp.NewClient()
	client.RequestLogHook = func(logger retryablehttp.Logger, req *http.Request, attempt int) {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	}

	ok, err := crawler.GenerateLicenseFile(client,
		licenseFileName,
		crawler.License{
			URL: "https://www.json.org/license.html",
		})

	if !ok {
		errStr := "Test has failed"
		if err != nil {
			errStr += fmt.Sprintf(", err: %s", err.Error())
		}
		assert.Fail(t, errStr)
	}
}

func TestRetryableHTTPClient(t *testing.T) {
	retryClient := retryablehttp.NewClient()

	// Set custom headers including User-Agent
	retryClient.RequestLogHook = func(logger retryablehttp.Logger, req *http.Request, attempt int) {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	}

	// Make the request
	resp, err := retryClient.Get("https://www.json.org/license.html")
	if err != nil {
		log.Fatalf("Error while fetching license Meta URL, error %v giving up after %d attempt(s)", err, retryClient.RetryMax)
	}
	defer resp.Body.Close()

	assert.Equal(t, resp.StatusCode, http.StatusOK, "Non-200 status code: %d", resp.StatusCode)
}
