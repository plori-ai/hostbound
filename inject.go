package hostbound

import (
	"cmp"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
)

func (b *binding) placeholders(yield func(string) bool) {
	if !yield(b.Placeholder) {
		return
	}
	for ph := range b.grants {
		if !yield(ph) {
			return
		}
	}
}

func (b *binding) match(h http.Header, escaped, decoded string) (presentedBinding, error) {
	m := presentedBinding{b: b}
	for _, inj := range b.Injects {
		for ph := range b.placeholders {
			if inj.Path {
				edits, err := b.pathEdits(escaped, decoded, ph)
				if err != nil {
					return m, err
				}
				if len(edits) == 0 {
					continue
				}
				if m.presented == "" || m.form.Path {
					m.multiple = m.multiple || m.presented != ""
					m.edits = append(m.edits, edits...)
				}
			} else if !inj.carries(h, ph) {
				continue
			}
			if m.presented == "" {
				m.form, m.presented = inj, ph
			}
			m.granted = m.granted || ph != b.Placeholder
		}
	}
	return m, nil
}

func (inj Injection) validate() error {
	switch {
	case inj.Path:
		if inj.Header != "" || inj.Prefix != "" || inj.BasicUser != "" {
			return errors.New("a path injection takes no Header, Prefix or BasicUser")
		}
	case inj.Header != "" && inj.BasicUser != "":
		return errors.New("set either Header or BasicUser, not both")
	case inj.BasicUser != "":
		if inj.Prefix != "" || strings.ContainsAny(inj.BasicUser, ":\r\n") {
			return errors.New("BasicUser must have no Prefix and no colon")
		}
	case inj.Header == "":
		return errors.New("set Header, BasicUser or Path")
	}
	return nil
}

func (inj Injection) headerName() string {
	if inj.BasicUser != "" {
		return "Authorization"
	}
	return http.CanonicalHeaderKey(inj.Header)
}

func (inj Injection) value(secret string) string {
	if inj.BasicUser != "" {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(inj.BasicUser+":"+secret))
	}
	return inj.Prefix + secret
}

func (inj Injection) carries(h http.Header, placeholder string) bool {
	for _, v := range h.Values(inj.headerName()) {
		if inj.matches(v, placeholder) {
			return true
		}
	}
	return false
}

func (inj Injection) matches(v, placeholder string) bool {
	if inj.BasicUser == "" {
		return v == inj.Prefix+placeholder
	}
	const scheme = "Basic "
	return len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) &&
		v[len(scheme):] == base64.StdEncoding.EncodeToString([]byte(inj.BasicUser+":"+placeholder))
}

func (inj Injection) apply(h http.Header, token string) {
	h.Set(inj.headerName(), inj.value(token))
}

func allowsPath(prefixes []string, path string) bool {
	if len(prefixes) == 0 {
		return true
	}
	lower := strings.ToLower(path)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%2e") {
		return false
	}
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	for _, prefix := range prefixes {
		if suffix, ok := strings.CutPrefix(path, prefix); prefix != "" && ok &&
			(suffix == "" || suffix[0] == '/' || suffix[0] == ':') {
			return true
		}
	}
	return false
}

const pathTokenChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/:"

type pathEdit struct {
	start, end int
	b          *binding
}

func escapedLen(raw string, decodedBytes int) int {
	i := 0
	for range decodedBytes {
		if raw[i] == '%' {
			i += 3
		} else {
			i++
		}
	}
	return i
}

func (b *binding) pathEdits(escaped, decoded, ph string) ([]pathEdit, error) {
	var edits []pathEdit
	offset := 0
	for {
		i := strings.Index(decoded, ph)
		if i < 0 {
			return edits, nil
		}
		start := offset + escapedLen(escaped[offset:], i)
		end := start + escapedLen(escaped[start:], len(ph))
		if escaped[start:end] != ph {
			return nil, errors.New("encoded path placeholder")
		}
		if len(edits) > 0 && start < edits[len(edits)-1].end {
			return nil, errors.New("overlapping path placeholders")
		}
		edits = append(edits, pathEdit{start, end, b})
		offset = start + escapedLen(escaped[start:], 1)
		decoded = decoded[i+1:]
	}
}

func selectedPathEdits(matches []presentedBinding) ([]pathEdit, error) {
	var edits []pathEdit
	var multiple bool
	for _, m := range matches {
		if m.inject {
			edits = append(edits, m.edits...)
			multiple = multiple || m.multiple
		}
	}
	slices.SortFunc(edits, func(a, b pathEdit) int { return cmp.Compare(a.start, b.start) })
	for i := 1; i < len(edits); i++ {
		if edits[i].start < edits[i-1].end {
			return nil, errors.New("overlapping path placeholders")
		}
	}
	if multiple {
		return nil, errors.New("multiple distinct path placeholders for binding")
	}
	return edits, nil
}

func applyPathEdits(escaped string, edits []pathEdit, injections map[*binding]matchedInjection) string {
	var path strings.Builder
	pos := 0
	for _, edit := range edits {
		path.WriteString(escaped[pos:edit.start])
		path.WriteString(injections[edit.b].token)
		pos = edit.end
	}
	path.WriteString(escaped[pos:])
	return path.String()
}
