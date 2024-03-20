package pom

import (
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

const cacheSize = 100000

type pomCache struct {
	mu    sync.Mutex
	cache *lru.Cache[string, *analysisResult]
}

func newPOMCache() *pomCache {
	cache, _ := lru.New[string, *analysisResult](cacheSize)
	return &pomCache{
		cache: cache,
	}
}

func (c *pomCache) put(art artifact, result analysisResult) {
	// c.mu.Lock()
	// defer c.mu.Unlock()
	c.cache.Add(c.key(art), &result)
}

func (c *pomCache) get(art artifact) *analysisResult {
	// c.mu.Lock()
	// defer c.mu.Unlock()
	result, ok := c.cache.Get(c.key(art))
	if !ok {
		return nil
	}
	return result
}

func (c *pomCache) key(art artifact) string {
	return fmt.Sprintf("%s:%s", art.Name, art.Version)
}
