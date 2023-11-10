package builder

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/deepfactor-io/javadb/pkg/crawler"
	"github.com/deepfactor-io/javadb/pkg/db"
	"github.com/deepfactor-io/javadb/pkg/fileutil"
	"github.com/deepfactor-io/javadb/pkg/types"
)

const updateInterval = time.Hour * 72 // 3 days
const licenseStringLimit = 150

type Builder struct {
	db    db.DB
	meta  db.Client
	clock clock.Clock
}

func NewBuilder(db db.DB, meta db.Client) Builder {
	return Builder{
		db:    db,
		meta:  meta,
		clock: clock.RealClock{},
	}
}

func (b *Builder) Build(cacheDir string) error {
	startTime := time.Now()
	indexDir := filepath.Join(cacheDir, types.IndexesDir)
	licenseDir := filepath.Join(cacheDir, types.LicenseDir)

	licenseFile, err := os.Open(licenseDir + types.NormalizedlicenseFileName)
	if err != nil {
		xerrors.Errorf("failed to open normalized license file: %w", err)
	}

	licenseMap := make(map[string]string)

	if err := json.NewDecoder(licenseFile).Decode(&licenseMap); err != nil {
		return xerrors.Errorf("failed to decode license file: %w", err)
	}

	count, err := fileutil.Count(indexDir)
	if err != nil {
		return xerrors.Errorf("count error: %w", err)
	}
	bar := pb.StartNew(count)
	defer log.Println("Build completed")
	// defer bar.Finish()

	var indexes []types.Index
	if err := fileutil.Walk(indexDir, func(r io.Reader, path string) error {
		index := &crawler.Index{}
		if err := json.NewDecoder(r).Decode(index); err != nil {
			return xerrors.Errorf("failed to decode index: %w", err)
		}
		for _, ver := range index.Versions {
			depArray := make([]types.Dependency, 0)
			for _, dep := range ver.Dependencies {
				depArray = append(depArray, types.Dependency{
					GroupID:    dep.GroupID,
					ArtifactID: dep.ArtifactID,
					Version:    dep.Version,
				})
			}
			indexes = append(indexes, types.Index{
				GroupID:      index.GroupID,
				ArtifactID:   index.ArtifactID,
				Version:      ver.Version,
				SHA1:         ver.SHA1,
				ArchiveType:  index.ArchiveType,
				License:      b.processLicenseInformationFromCache(ver.License, licenseDir, licenseMap),
				Dependencies: depArray,
			})
		}
		bar.Increment()

		if len(indexes) > 1000 {
			if err = b.db.InsertIndexes(indexes); err != nil {
				return xerrors.Errorf("failed to insert index to db: %w", err)
			}
			indexes = []types.Index{}
		}
		return nil
	}); err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	// Insert the remaining indexes
	if err = b.db.InsertIndexes(indexes); err != nil {
		return xerrors.Errorf("failed to insert index to db: %w", err)
	}

	bar.Finish()

	fmt.Println("Inserting dependencies now .......")
	bar2 := pb.StartNew(count)
	defer bar2.Finish()

	// Insert dependencies
	indexes = []types.Index{}
	if err := fileutil.Walk(indexDir, func(r io.Reader, path string) error {
		index := &crawler.Index{}
		if err := json.NewDecoder(r).Decode(index); err != nil {
			return xerrors.Errorf("failed to decode index: %w", err)
		}
		for _, ver := range index.Versions {
			depArray := make([]types.Dependency, 0)
			for _, dep := range ver.Dependencies {
				depArray = append(depArray, types.Dependency{
					GroupID:    dep.GroupID,
					ArtifactID: dep.ArtifactID,
					Version:    dep.Version,
				})
			}
			indexes = append(indexes, types.Index{
				GroupID:      index.GroupID,
				ArtifactID:   index.ArtifactID,
				Version:      ver.Version,
				Dependencies: depArray,
			})
		}
		bar2.Increment()

		if len(indexes) > 10 {
			for _, index := range indexes {
				for _, dep := range index.Dependencies {
					if err = b.db.InsertDependencies(index, dep); err != nil {
						fmt.Errorf("unable to insert to 'dependencies' table: %w", err)
					}
				}
			}

			indexes = []types.Index{}
			return nil
		}
		return nil
	}); err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	// Insert the remaining index dependencies
	for _, index := range indexes {
		for _, dep := range index.Dependencies {
			if err = b.db.InsertDependencies(index, dep); err != nil {
				fmt.Errorf("unable to insert to 'dependencies' table: %w", err)
			}
		}
	}

	if err := b.db.VacuumDB(); err != nil {
		return xerrors.Errorf("fauled to vacuum db: %w", err)
	}

	// save metadata
	metaDB := db.Metadata{
		Version:    db.SchemaVersion,
		NextUpdate: b.clock.Now().UTC().Add(updateInterval),
		UpdatedAt:  b.clock.Now().UTC(),
	}
	if err := b.meta.Update(metaDB); err != nil {
		return xerrors.Errorf("failed to update metadata: %w", err)
	}

	// Calculate the elapsed time
	elapsedTime := time.Since(startTime)

	// Print the time taken
	fmt.Println("=============================================================")
	fmt.Println("=============================================================")
	fmt.Printf("This action took %s to run.\n", elapsedTime)
	fmt.Println("=============================================================")
	fmt.Println("=============================================================")

	return nil
}

// processLicenseInformationFromCache : gets cached license information by license key and updates the records to be inserted
func (b *Builder) processLicenseInformationFromCache(license, licenseDir string, licenseMap map[string]string) string {
	var updatedLicenseList []string
	// process license information
	for _, l := range strings.Split(license, "|") {
		if val, ok := licenseMap[l]; ok {
			val = strings.TrimSpace(val)
			updatedLicenseList = append(updatedLicenseList, val)
		}
	}

	// precautionary check
	// return first <licenseStringLimit> characters if license string is too long
	result := strings.Join(updatedLicenseList, "|")
	if len(result) > licenseStringLimit {
		r := []rune(result)
		if len(r) > licenseStringLimit {
			log.Printf("untrimmed license string: %s", result)
			return string(r[:licenseStringLimit])
		}

	}

	return result

}
