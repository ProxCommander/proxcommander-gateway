// Package audit sets up the gateway's JSON-lines logger. Request records
// carry time, remote, method, path, status, duration and node only: never
// headers, bodies, query strings or credentials.
package audit

import (
	"io"
	"log/slog"
	"os"
)

// Open returns a JSON logger writing to stdout and, if path is set, appending
// to that file (created with mode 0600). The returned close func closes the file.
func Open(stdout io.Writer, path string) (*slog.Logger, func() error, error) {
	w := stdout
	closeFn := func() error { return nil }
	if path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return nil, nil, err
		}
		w = io.MultiWriter(stdout, f)
		closeFn = f.Close
	}
	return slog.New(slog.NewJSONHandler(w, nil)), closeFn, nil
}
