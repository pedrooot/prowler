package compliance

import (
	"embed"
	"io/fs"
	"sync"
)

//go:embed frameworks
var embedded embed.FS

var (
	loadOnce sync.Map // provider -> *loaded
)

type loaded struct {
	once sync.Once
	set  Set
	err  error
}

// ForProvider returns the frameworks of a provider, reading and parsing them
// on first use so a scan only pays for the provider it targets.
func ForProvider(provider string) (Set, error) {
	entry, _ := loadOnce.LoadOrStore(provider, &loaded{})
	l := entry.(*loaded)
	l.once.Do(func() {
		root, err := fs.Sub(embedded, "frameworks")
		if err != nil {
			l.err = err
			return
		}
		l.set, l.err = Load(root, provider)
	})
	return l.set, l.err
}

// Providers lists the providers that ship compliance frameworks.
func Providers() []string {
	entries, err := fs.ReadDir(embedded, "frameworks")
	if err != nil {
		return nil
	}
	providers := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			providers = append(providers, entry.Name())
		}
	}
	return providers
}
