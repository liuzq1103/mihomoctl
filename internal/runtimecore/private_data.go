package runtimecore

import (
	"io"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

const fileJournalLimit int64 = 64 << 20
const compoundJournalLimit int64 = 128 << 20

// Journals hold base64 snapshots of multiple bounded YAML documents. Their
// metadata limit is separate from the single-document YAML parsing limit.
func readPrivateBounded(p string, limit int64) ([]byte, error) {
	if e := platform.CheckPath(p); e != nil {
		return nil, e
	}
	f, e := openPrivateRegular(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if e = checkLogInfo(st); e != nil {
		return nil, platform.Usage("journal-file-untrusted")
	}
	if st.Size() > limit {
		return nil, platform.Usage("journal-too-large")
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(raw)) > limit {
		return nil, platform.Usage("journal-too-large")
	}
	return raw, nil
}
