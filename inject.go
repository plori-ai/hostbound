package hostbound

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

func (inj Injection) validate() error {
	switch {
	case inj.Header != "" && inj.BasicUser != "":
		return errors.New("set either Header or BasicUser, not both")
	case inj.BasicUser != "":
		if inj.Prefix != "" || strings.ContainsAny(inj.BasicUser, ":\r\n") {
			return errors.New("BasicUser must have no Prefix and no colon")
		}
	case inj.Header == "":
		return errors.New("set Header or BasicUser")
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
