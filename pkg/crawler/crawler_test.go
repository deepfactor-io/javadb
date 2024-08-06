package crawler_test

import (
	"context"
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

			// GAV index file check
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

func TestGenerateLicenseFile(t *testing.T) {
	licenseFileName := "test_generate_license.txt"
	defer func() {
		if _, err := os.Stat(licenseFileName); err == nil {
			// remove the test file
			os.Remove(licenseFileName)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	classifier, err := backend.New()
	if err != nil {
		t.Logf("failed to initialize classifier, err: %s", err.Error())
		return
	}

	client := retryablehttp.NewClient()
	client.RequestLogHook = crawler.GetRequestLogHookForLicenses(client)

	// Test License URL-1
	t.Run("LicenseURL Test1", func(t *testing.T) {
		ok, err := crawler.GenerateLicenseFile(
			client,
			licenseFileName,
			crawler.License{
				URL: "https://www.json.org/license.html",
			})

		if err != nil {
			assert.Fail(t, "%s has failed, err: %s", t.Name(), err.Error())
		}
		if !ok {
			assert.Fail(t, "%s has failed", t.Name())
		}

		errs := classifier.ClassifyLicensesWithContext(ctx, 1, []string{licenseFileName}, true)
		if len(errs) > 0 {
			t.Log("errors in license classification ", errs)
			return
		}

		// extract results
		results := classifier.GetResults()
		sort.Sort(results)

		assert.Equal(t, true, len(results) != 0, "No results were found by the classifier")

		expectedLicense := "JSON"
		foundExpectedLicense := false
		for _, result := range results {
			if result.Name == expectedLicense {
				foundExpectedLicense = true
				break
			}
		}
		assert.Equal(t, true, foundExpectedLicense, "could not find expected license in classifier results, expected: %s", expectedLicense)
	})

	// Test License URL-2
	t.Run("LicenseURL Test2", func(t *testing.T) {
		ok, err := crawler.GenerateLicenseFile(
			client,
			licenseFileName,
			crawler.License{
				URL: "https://www.snmp4j.org/GPL.txt",
			})

		if err != nil {
			assert.Fail(t, "%s has failed, err: %s", t.Name(), err.Error())
		}
		if !ok {
			assert.Fail(t, "%s has failed", t.Name())
		}

		errs := classifier.ClassifyLicensesWithContext(ctx, 1, []string{licenseFileName}, true)
		if len(errs) > 0 {
			t.Log("errors in license classification ", errs)
			return
		}

		// extract results
		results := classifier.GetResults()
		sort.Sort(results)

		assert.Equal(t, true, len(results) != 0, "No results were found by the classifier")

		expectedLicense := "GPL-2.0"
		foundExpectedLicense := false
		for _, result := range results {
			t.Log("License finding: ", result.Name)

			if result.Name == expectedLicense {
				foundExpectedLicense = true
				break
			}
		}
		assert.Equal(t, true, foundExpectedLicense, "could not find expected license in classifier results, expected: %s", expectedLicense)
	})
}

func TestRetryableHTTPClient(t *testing.T) {
	retryClient := retryablehttp.NewClient()

	// Set custom request LogHook as needed
	retryClient.RequestLogHook = crawler.GetRequestLogHookForLicenses(retryClient)

	request, err := retryablehttp.NewRequest("GET", "https://www.json.org/license.html", nil)
	if err != nil {
		t.Log("failed to create request, error: ", err)
		return
	}

	// Make the request
	resp, err := retryClient.Do(request)
	if err != nil {
		t.Logf("Error while fetching license Meta URL, error %v", err)
		return
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Non-200 status code: %d", resp.StatusCode)
}
