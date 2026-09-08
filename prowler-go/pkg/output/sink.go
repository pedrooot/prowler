package output

import (
	"errors"
	"io"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
)

// Writer is an output format that consumes findings one at a time.
type Writer interface {
	Write(f *finding.Finding) error
	Close() error
}

// Multi fans one stream of findings out to every configured format.
type Multi struct {
	writers []Writer
	closers []io.Closer
}

func NewMulti(writers ...Writer) *Multi { return &Multi{writers: writers} }

// OwnFile makes the sink responsible for closing an underlying file once the
// scan is done.
func (m *Multi) OwnFile(c io.Closer) { m.closers = append(m.closers, c) }

func (m *Multi) Write(f *finding.Finding) error {
	var errs error
	for _, w := range m.writers {
		if err := w.Write(f); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (m *Multi) Close() error {
	var errs error
	for _, w := range m.writers {
		errs = errors.Join(errs, w.Close())
	}
	for _, c := range m.closers {
		errs = errors.Join(errs, c.Close())
	}
	return errs
}
