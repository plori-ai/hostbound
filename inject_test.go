package hostbound

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

var (
	bearerInjection = Injection{Header: "Authorization", Prefix: "Bearer "}
	tokenInjection  = Injection{Header: "Authorization", Prefix: "token "}
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
	"token " + placeholder,
	"token  " + placeholder,
	"Basic " + b64("other:"+placeholder),
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
	b := binding{Binding: Binding{Placeholder: placeholder, Injects: []Injection{basicInjection, tokenInjection, bearerInjection, {BasicUser: "other"}}}}
	f.Fuzz(func(t *testing.T, v string) {
		scheme, encoded, _ := strings.Cut(v, " ")
		isBasic := len(scheme) == len("Basic") && strings.EqualFold(scheme, "Basic")
		var want string
		switch {
		case v == "Bearer "+placeholder:
			want = "Bearer " + realToken
		case v == "token "+placeholder:
			want = "token " + realToken
		case isBasic && encoded == b64(basicUser+":"+placeholder):
			want = "Basic " + b64(basicUser+":"+realToken)
		case isBasic && encoded == b64("other:"+placeholder):
			want = "Basic " + b64("other:"+realToken)
		}
		h := http.Header{"Authorization": {v}}
		form, presented, _ := b.match(h)
		ok := presented != ""
		if ok != (want != "") {
			t.Fatalf("match(%q) = %v, want injection %v", v, ok, want != "")
		}
		if ok {
			form.apply(h, realToken)
			if got := h.Get("Authorization"); got != want {
				t.Fatalf("injected %q for %q, want %q", got, v, want)
			}
		}
	})
}
