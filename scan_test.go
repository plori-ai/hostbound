package hostbound

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

func testReplacer(secrets ...string) *replacer {
	var pairs []secretPair
	for _, s := range secrets {
		pairs = append(pairs, secretPair{[]byte(s), []byte(placeholder)})
	}
	return newReplacer(pairs)
}

func scanAll(t *testing.T, r *replacer, src io.Reader) string {
	t.Helper()
	b := &scanBody{src: src, closer: io.NopCloser(nil), r: r, onEOF: func() {}, in: make([]byte, 7)}
	out, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestReplacerStreams(t *testing.T) {
	inputs := []string{
		realToken,
		"x" + realToken + "y" + realToken,
		realToken[:5] + realToken,
		"rrrr" + realToken + realToken[:9],
		strings.Repeat(realToken[:3], 5) + realToken,
		"no secret here",
		"",
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for _, in := range inputs {
		want := strings.ReplaceAll(in, realToken, placeholder)
		if got := scanAll(t, testReplacer(realToken), iotest.OneByteReader(strings.NewReader(in))); got != want {
			t.Errorf("one byte at a time: %q -> %q, want %q", in, got, want)
		}
		for range 20 {
			r := testReplacer(realToken)
			var out []byte
			rest := []byte(in)
			for len(rest) > 0 {
				n := 1 + rng.IntN(len(rest))
				out = r.feed(out, rest[:n], false)
				rest = rest[n:]
			}
			out = r.feed(out, nil, true)
			if string(out) != want {
				t.Fatalf("chunked: %q -> %q, want %q", in, out, want)
			}
		}
	}
}

func TestReplacerHoldsBackOnlyPossibleSecretPrefix(t *testing.T) {
	r := testReplacer(realToken)
	if out := r.feed(nil, []byte("data: done\n\n"), false); string(out) != "data: done\n\n" {
		t.Fatalf("held back %q", out)
	}
	if out := r.feed(nil, []byte("x"+realToken[:4]), false); string(out) != "x" {
		t.Fatalf("emitted %q", out)
	}
}

func TestReplacerSeveralSecrets(t *testing.T) {
	r := testReplacer("abc", "abcdef", "zz")
	if got := string(r.feed(nil, []byte("abcdef abc zzz"), true)); got != placeholder+" "+placeholder+" "+placeholder+"z" {
		t.Fatalf("got %q", got)
	}
}

func TestScanBodyDropsHeldBytesOnError(t *testing.T) {
	src := io.MultiReader(strings.NewReader("ok "+realToken[:6]), iotest.ErrReader(errors.New("reset")))
	b := &scanBody{src: src, closer: io.NopCloser(nil), r: testReplacer(realToken), onEOF: func() {}, in: make([]byte, 64)}
	out, err := io.ReadAll(b)
	if err == nil || string(out) != "ok " {
		t.Fatalf("got %q, %v", out, err)
	}
}

func TestScanResponseHeaders(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"X-A": {"a " + realToken, "b"}, "Set-Cookie": {"t=" + realToken}},
		Body:       http.NoBody,
	}
	if err := scanResponse(resp, testReplacer(realToken)); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Values("X-A")[0] != "a "+placeholder || resp.Header.Get("Set-Cookie") != "t="+placeholder || resp.Body != http.NoBody {
		t.Fatalf("headers %v", resp.Header)
	}
}

func TestReplacerOverlappingSecrets(t *testing.T) {
	const short, long = "example-key", "example-key-extended"
	h := http.Header{"X-Fixture": {long, "a " + short + " b"}}
	testReplacer(short, long).replaceHeader(h)
	if got := h.Values("X-Fixture"); got[0] != placeholder || got[1] != "a "+placeholder+" b" {
		t.Fatalf("header %q", got)
	}
	for _, chunks := range [][]string{{long}, {short, "-extended"}, {"exa", "mple-key", "-ext", "ended"}, {short, "!"}} {
		r := testReplacer(short, long)
		var out []byte
		for _, c := range chunks {
			out = r.feed(out, []byte(c), false)
		}
		out = r.feed(out, nil, true)
		want := strings.ReplaceAll(strings.ReplaceAll(strings.Join(chunks, ""), long, placeholder), short, placeholder)
		if string(out) != want {
			t.Fatalf("%q: got %q, want %q", chunks, out, want)
		}
	}
}

func TestScanResponseFieldNames(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{http.CanonicalHeaderKey("x-" + realToken): {"v"}, "X-Plain": {"w"}},
		Trailer:    http.Header{http.CanonicalHeaderKey("x-tail-" + realToken): {"t"}},
		Body:       http.NoBody,
	}
	if err := scanResponse(resp, testReplacer(realToken)); err != nil {
		t.Fatal(err)
	}
	for _, h := range []http.Header{resp.Header, resp.Trailer} {
		for name := range h {
			if strings.Contains(strings.ToLower(name), realToken) {
				t.Fatalf("name %q kept the token", name)
			}
		}
	}
	if resp.Header.Get("X-"+placeholder) != "v" || resp.Header.Get("X-Plain") != "w" || resp.Trailer.Get("X-Tail-"+placeholder) != "t" {
		t.Fatalf("header %v trailer %v", resp.Header, resp.Trailer)
	}
}

func TestReplacerMatchesWholeInputOnAnySplit(t *testing.T) {
	word := func(r *rand.Rand, alphabet string, minLen, maxLen int) []byte {
		b := make([]byte, minLen+r.IntN(maxLen-minLen+1))
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}
		return b
	}
	r := rand.New(rand.NewPCG(1, 2))
	for n := range 20000 {
		var pairs []secretPair
		for range 1 + r.IntN(4) {
			pairs = append(pairs, secretPair{word(r, "ab", 1, 8), word(r, "XY", 1, 6)})
		}
		input := word(r, "abX", 0, 64)
		var want []byte
		for i := 0; i < len(input); {
			best := -1
			for j, p := range pairs {
				if bytes.HasPrefix(input[i:], p.secret) && (best < 0 || len(p.secret) > len(pairs[best].secret)) {
					best = j
				}
			}
			if best < 0 {
				want = append(want, input[i])
				i++
				continue
			}
			want = append(want, pairs[best].placeholder...)
			i += len(pairs[best].secret)
		}
		rep := newReplacer(pairs)
		var got []byte
		for rest, final := input, false; !final; {
			k := r.IntN(len(rest) + 1)
			final = k == len(rest)
			got = rep.feed(got, rest[:k], final)
			rest = rest[k:]
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: pairs %q, input %q: got %q, want %q", n, pairs, input, got, want)
		}
	}
}
