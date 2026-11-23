package hostbound

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

var (
	bearerInjection = Injection{Header: "Authorization", Prefix: "Bearer "}
	basicInjection  = Injection{BasicUser: basicUser}
	keyInjection    = Injection{Header: "x-api-key"}
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

var locationSeeds = []string{
	"Bearer " + placeholder,
	"bearer " + placeholder,
	"Bearer  " + placeholder,
	"Bearer " + placeholder + " ",
	"Bearer " + placeholder + "x",
	"Bearer " + placeholder[:len(placeholder)-1],
	"Token " + placeholder,
	placeholder,
	"Basic " + b64(basicUser+":"+placeholder),
	"basic " + b64(basicUser+":"+placeholder),
	"BASIC " + b64(basicUser+":"+placeholder),
	"Basic  " + b64(basicUser+":"+placeholder),
	"Basic " + strings.TrimRight(b64(basicUser+":"+placeholder), "="),
	"Basic " + base64.URLEncoding.EncodeToString([]byte(basicUser+":"+placeholder)),
	"Basic " + b64(basicUser+":"+placeholder+":x"),
	"Basic " + b64(basicUser+"x:"+placeholder),
	"Basic " + b64(":"+placeholder),
	"Basic " + b64(placeholder+":"+basicUser),
	"Basic " + b64(basicUser+":"+placeholder+"\n"),
	"Basic " + b64(basicUser+":"+placeholder) + "=",
	"Basic",
	"Basic ",
	"Basic !!!",
}

func TestDeclaredLocation(t *testing.T) {
	for _, tc := range []struct {
		inj    Injection
		values []string
		want   bool
	}{
		{bearerInjection, []string{"Bearer " + placeholder}, true},
		{bearerInjection, []string{"other", "Bearer " + placeholder}, true},
		{bearerInjection, []string{"bearer " + placeholder}, false},
		{bearerInjection, []string{"Bearer " + placeholder + " "}, false},
		{bearerInjection, []string{placeholder}, false},
		{keyInjection, []string{placeholder}, true},
		{keyInjection, []string{"Bearer " + placeholder}, false},
		{basicInjection, []string{"Basic " + b64(basicUser+":"+placeholder)}, true},
		{basicInjection, []string{"basic " + b64(basicUser+":"+placeholder)}, true},
		{basicInjection, []string{"Basic " + strings.TrimRight(b64(basicUser+":"+placeholder), "=")}, false},
		{basicInjection, []string{"Basic " + b64(basicUser+":"+placeholder+":x")}, false},
		{basicInjection, []string{"Basic " + b64(placeholder+":x")}, false},
		{basicInjection, []string{"Bearer " + placeholder}, false},
	} {
		h := http.Header{}
		for _, v := range tc.values {
			h.Add(tc.inj.headerName(), v)
		}
		if got := tc.inj.carries(h, placeholder); got != tc.want {
			t.Errorf("%+v %q: carries = %v, want %v", tc.inj, tc.values, got, tc.want)
		}
		if !tc.want {
			continue
		}
		tc.inj.apply(h, realToken)
		if vs := h.Values(tc.inj.headerName()); len(vs) != 1 || vs[0] != tc.inj.value(realToken) {
			t.Errorf("%+v: after apply %q", tc.inj, vs)
		}
	}
	h := http.Header{"X-Other": {"Bearer " + placeholder}}
	if bearerInjection.carries(h, placeholder) {
		t.Error("placeholder in another header matched")
	}
}

func FuzzDeclaredLocation(f *testing.F) {
	for _, s := range locationSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if got, want := bearerInjection.matches(v, placeholder), v == "Bearer "+placeholder; got != want {
			t.Fatalf("bearer match(%q) = %v", v, got)
		}
		basic := basicInjection.matches(v, placeholder)
		if basic {
			raw, err := base64.StdEncoding.DecodeString(v[len("Basic "):])
			if err != nil || string(raw) != basicUser+":"+placeholder || !strings.EqualFold(v[:len("Basic ")], "Basic ") {
				t.Fatalf("basic matched %q", v)
			}
		}
		if (basic || bearerInjection.matches(v, placeholder)) && !strings.Contains(v, placeholder) && !strings.Contains(v, b64(basicUser+":"+placeholder)) {
			t.Fatalf("matched %q without the placeholder", v)
		}
		for _, inj := range []Injection{bearerInjection, basicInjection} {
			h := http.Header{}
			h.Set(inj.headerName(), v)
			if !inj.carries(h, placeholder) {
				continue
			}
			inj.apply(h, realToken)
			out := h.Get(inj.headerName())
			if strings.Contains(out, placeholder) || out != inj.value(realToken) {
				t.Fatalf("apply on %q gave %q", v, out)
			}
		}
	})
}
