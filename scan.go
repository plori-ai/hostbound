package hostbound

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
)

var errUnscannable = errors.New("hostbound: response encoding cannot be scanned")

type secretPair struct{ secret, placeholder []byte }

type replacer struct {
	pairs  []secretPair
	maxLen int
	carry  []byte
}

func newReplacer(pairs []secretPair) *replacer {
	r := &replacer{}
	for _, p := range pairs {
		if len(p.secret) == 0 {
			continue
		}
		r.pairs = append(r.pairs, p)
		r.maxLen = max(r.maxLen, len(p.secret))
	}
	return r
}

func (r *replacer) next(buf []byte) (int, *secretPair) {
	at, hit := -1, (*secretPair)(nil)
	for i := range r.pairs {
		p := &r.pairs[i]
		j := bytes.Index(buf, p.secret)
		if j >= 0 && (at < 0 || j < at || (j == at && len(p.secret) > len(hit.secret))) {
			at, hit = j, p
		}
	}
	return at, hit
}

func (r *replacer) partial(buf []byte) int {
	for k := min(len(buf), r.maxLen-1); k > 0; k-- {
		tail := buf[len(buf)-k:]
		for _, p := range r.pairs {
			if len(tail) < len(p.secret) && bytes.HasPrefix(p.secret, tail) {
				return k
			}
		}
	}
	return 0
}

func (r *replacer) feed(dst, p []byte, final bool) []byte {
	buf := append(r.carry, p...)
	hold := len(buf)
	if !final {
		hold -= r.partial(buf)
	}
	for {
		i, hit := r.next(buf)
		if hit == nil || i >= hold {
			break
		}
		dst = append(dst, buf[:i]...)
		dst = append(dst, hit.placeholder...)
		n := i + len(hit.secret)
		buf = buf[n:]
		hold = max(hold-n, 0)
	}
	dst = append(dst, buf[:hold]...)
	r.carry = bytes.Clone(buf[hold:])
	return dst
}

func replaceAll(pairs []secretPair, s string) string {
	r := newReplacer(pairs)
	return string(r.feed(nil, []byte(s), true))
}

func (r *replacer) replaceString(s string) string { return replaceAll(r.pairs, s) }

func (r *replacer) replaceName(name string) string {
	lower := strings.ToLower(name)
	pairs := make([]secretPair, len(r.pairs))
	for i, p := range r.pairs {
		pairs[i] = secretPair{bytes.ToLower(p.secret), p.placeholder}
	}
	if out := replaceAll(pairs, lower); out != lower {
		return http.CanonicalHeaderKey(out)
	}
	return name
}

func (r *replacer) replaceHeader(h http.Header) {
	for name, vs := range h {
		for i, v := range vs {
			vs[i] = r.replaceString(v)
		}
		if renamed := r.replaceName(name); renamed != name {
			delete(h, name)
			h[renamed] = append(h[renamed], vs...)
		}
	}
}

type scanBody struct {
	src     io.Reader
	closer  io.Closer
	r       *replacer
	onEOF   func()
	in, out []byte
	pending []byte
	err     error
}

func (b *scanBody) Read(p []byte) (int, error) {
	for len(b.pending) == 0 && b.err == nil {
		n, err := b.src.Read(b.in)
		switch {
		case err == io.EOF:
			b.out = b.r.feed(b.out[:0], b.in[:n], true)
			b.onEOF()
		case err != nil:
			b.out = b.out[:0]
		default:
			b.out = b.r.feed(b.out[:0], b.in[:n], false)
		}
		b.pending, b.err = b.out, err
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	if len(b.pending) == 0 && b.err != nil {
		return n, b.err
	}
	return n, nil
}

func (b *scanBody) Close() error { return b.closer.Close() }

func scanResponse(resp *http.Response, r *replacer) error {
	r.replaceHeader(resp.Header)
	r.replaceHeader(resp.Trailer)
	if resp.StatusCode == http.StatusSwitchingProtocols || resp.Body == http.NoBody {
		return nil
	}
	var src io.Reader = resp.Body
	enc := resp.Header.Values("Content-Encoding")
	if len(enc) > 1 {
		return errUnscannable
	}
	switch strings.ToLower(strings.TrimSpace(strings.Join(enc, ""))) {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return errUnscannable
		}
		src = zr
		resp.Header.Del("Content-Encoding")
	default:
		return errUnscannable
	}
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Body = &scanBody{
		src:    src,
		closer: resp.Body,
		r:      r,
		onEOF:  func() { r.replaceHeader(resp.Trailer) },
		in:     make([]byte, 32<<10),
	}
	return nil
}
