package pom

import (
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

const cacheSize int = 72000

type PomCache struct {
	mu       *sync.RWMutex
	cache    *lru.Cache[string, *analysisResult]
	urlCache *lru.Cache[string, *pomXML]
}

func NewPOMCache() *PomCache {
	cache, _ := lru.New[string, *analysisResult](cacheSize)
	urlCache, _ := lru.New[string, *pomXML](cacheSize)

	return &PomCache{
		cache:    cache,
		urlCache: urlCache,
		mu:       &sync.RWMutex{},
	}
}

func (c *PomCache) put(art artifact, result analysisResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Add(c.key(art), &result)
}

func (c *PomCache) get(art artifact) *analysisResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result, ok := c.cache.Get(c.key(art))
	if !ok {
		return nil
	}
	return result
}

func (c *PomCache) putPomXML(url string, pomXML *pomXML) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.urlCache.Add(url, pomXML)
}

func (c *PomCache) getPomXML(url string) *pomXML {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pomXML, ok := c.urlCache.Get(url)
	if !ok {
		return nil
	}

	return pomXML
}

func (c *PomCache) key(art artifact) string {
	return fmt.Sprintf("%s:%s", art.Name(), art.Version.String())
}
