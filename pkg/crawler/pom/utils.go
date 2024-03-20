package pom

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	dio "github.com/deepfactor-io/go-dep-parser/pkg/io"
	"golang.org/x/xerrors"
)

func NewReadSeekerAt(r io.Reader) (dio.ReadSeekerAt, error) {
	if rr, ok := r.(dio.ReadSeekerAt); ok {
		return rr, nil
	}

	buff := bytes.NewBuffer([]byte{})
	if _, err := io.Copy(buff, r); err != nil {
		return nil, xerrors.Errorf("copy error: %w", err)
	}

	return bytes.NewReader(buff.Bytes()), nil
}

func isProperty(version string) bool {
	if version != "" && strings.HasPrefix(version, "${") && strings.HasSuffix(version, "}") {
		return true
	}
	return false
}

func packageID(name, version string) string {
	return fmt.Sprintf("%s:%s", name, version)
}

func UniqueStrings(ss []string) []string {
	var results []string
	uniq := map[string]struct{}{}
	for _, s := range ss {
		if _, ok := uniq[s]; ok {
			continue
		}
		results = append(results, s)
		uniq[s] = struct{}{}
	}
	return results
}

func MergeMaps(parent, child map[string]string) map[string]string {
	if parent == nil {
		return child
	}
	for k, v := range child {
		parent[k] = v
	}
	return parent
}
