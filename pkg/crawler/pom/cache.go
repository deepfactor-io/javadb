package pom

import (
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

const cacheSize = 10000

type PomCache struct {
	mu    sync.Mutex
	cache *lru.Cache[string, *analysisResult]
}

func NewPOMCache() *PomCache {
	cache, _ := lru.New[string, *analysisResult](cacheSize)
	return &PomCache{
		cache: cache,
	}
}

func (c *PomCache) put(art artifact, result analysisResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Add(c.key(art), &result)
}

func (c *PomCache) get(art artifact) *analysisResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	result, ok := c.cache.Get(c.key(art))
	if !ok {
		return nil
	}
	return result
}

func (c *PomCache) key(art artifact) string {
	return fmt.Sprintf("%s:%s", art.Name(), art.Version.String())
}
