package db

import (
	"database/sql"
	"os"
	"path/filepath"

	"github.com/deepfactor-io/javadb/pkg/types"
	"golang.org/x/xerrors"
)

const (
	dependencyDbFileName = "df-java-dependency.db"
)

func NewDbWithDependency(cacheDir string) (DB, error) {
	dbPath := filepath.Join(cacheDir, dependencyDbFileName)
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return DB{}, xerrors.Errorf("failed to mkdir: %w", err)
	}

	// open db
	var err error
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return DB{}, xerrors.Errorf("can't open db: %w", err)
	}

	if _, err = db.Exec("PRAGMA foreign_keys=true"); err != nil {
		return DB{}, xerrors.Errorf("failed to enable 'foreign_keys': %w", err)
	}

	return DB{
		client: db,
		dir:    dbDir,
	}, nil
}

func (db *DB) InitDbWithDependency() error {
	if _, err := db.client.Exec("CREATE TABLE artifacts(id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts' table: %w", err)
	}
	if _, err := db.client.Exec("CREATE TABLE indices(artifact_id INTEGER, version TEXT, sha1 BLOB, dependency TEXT, foreign key (artifact_id) references artifacts(id))"); err != nil {
		return xerrors.Errorf("unable to create 'indices' table: %w", err)
	}
	if _, err := db.client.Exec("CREATE UNIQUE INDEX artifacts_idx ON artifacts(artifact_id, group_id)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts_idx' index: %w", err)
	}
	if _, err := db.client.Exec("CREATE INDEX indices_artifact_idx ON indices(artifact_id)"); err != nil {
		return xerrors.Errorf("unable to create 'indices_artifact_idx' index: %w", err)
	}
	if _, err := db.client.Exec("CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1)"); err != nil {
		return xerrors.Errorf("unable to create 'indices_sha1_idx' index: %w", err)
	}
	return nil
}

func (db *DB) InsertIndexesWithDependency(indexes []types.Index) error {
	if len(indexes) == 0 {
		return nil
	}
	tx, err := db.client.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err = db.insertArtifacts(tx, indexes); err != nil {
		return xerrors.Errorf("insert error: %w", err)
	}

	for _, index := range indexes {
		_, err = tx.Exec(`
			INSERT INTO indices(artifact_id, version, sha1, dependency)
			VALUES (
			        (SELECT id FROM artifacts
			            WHERE group_id=? AND artifact_id=?),
			        ?, ?, ?
			) ON CONFLICT(sha1) DO NOTHING`,
			index.GroupID, index.ArtifactID, index.Version, index.SHA1, index.Dependency)
		if err != nil {
			return xerrors.Errorf("unable to insert to 'indices' table: %w", err)
		}
	}

	return tx.Commit()
}
