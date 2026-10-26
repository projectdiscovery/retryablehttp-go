package retryablehttp

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDigestAuthorization(t *testing.T) {
	const (
		rfc2617Challenge = `Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"`
		rfc2617Fields    = `username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html"`
		rfc7616Challenge = `realm="http-auth@example.org", qop="auth, auth-int", nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"`
		rfc7616Fields    = `username="Mufasa", realm="http-auth@example.org", nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", uri="/dir/index.html"`
		rfc7616Cnonce    = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
		rfc7616Opaque    = `opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"`
	)
	mufasa := &Auth{Type: DigestAuth, Username: "Mufasa", Password: "Circle Of Life"}

	tests := []struct {
		name       string
		challenges []string
		auth       *Auth
		method     string
		uri        string
		body       string
		cnonce     string
		want       string
	}{
		{
			name:       "RFC 2617 example prefers auth over auth-int",
			challenges: []string{rfc2617Challenge},
			auth:       mufasa,
			method:     http.MethodGet,
			uri:        "/dir/index.html",
			cnonce:     "0a4f113b",
			want:       `Digest ` + rfc2617Fields + `, qop=auth, nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1", opaque="5ccc069c403ebaf9f0171e9517f40e41"`,
		},
		{
			name:       "RFC 7616 MD5 example",
			challenges: []string{`Digest algorithm=MD5, ` + rfc7616Challenge},
			auth:       &Auth{Type: DigestAuth, Username: "Mufasa", Password: "Circle of Life"},
			method:     http.MethodGet,
			uri:        "/dir/index.html",
			cnonce:     rfc7616Cnonce,
			want:       `Digest ` + rfc7616Fields + `, algorithm=MD5, qop=auth, nc=00000001, cnonce="` + rfc7616Cnonce + `", response="8ca523f5e9506fed4657c9700eebdbec", ` + rfc7616Opaque,
		},
		{
			name: "RFC 7616 SHA-256 example picks the first supported challenge",
			challenges: []string{
				`Basic realm="other", Digest algorithm=SHA-256, ` + rfc7616Challenge,
				`Digest algorithm=MD5, ` + rfc7616Challenge,
			},
			auth:   &Auth{Type: DigestAuth, Username: "Mufasa", Password: "Circle of Life"},
			method: http.MethodGet,
			uri:    "/dir/index.html",
			cnonce: rfc7616Cnonce,
			want:   `Digest ` + rfc7616Fields + `, algorithm=SHA-256, qop=auth, nc=00000001, cnonce="` + rfc7616Cnonce + `", response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1", ` + rfc7616Opaque,
		},
		{
			name:       "challenges in one value keep their own parameters",
			challenges: []string{`Digest realm="x", nonce="y", algorithm=SHA-1, userhash=true, Digest algorithm=MD5, ` + rfc7616Challenge},
			auth:       &Auth{Type: DigestAuth, Username: "Mufasa", Password: "Circle of Life"},
			method:     http.MethodGet,
			uri:        "/dir/index.html",
			cnonce:     rfc7616Cnonce,
			want:       `Digest ` + rfc7616Fields + `, algorithm=MD5, qop=auth, nc=00000001, cnonce="` + rfc7616Cnonce + `", response="8ca523f5e9506fed4657c9700eebdbec", ` + rfc7616Opaque,
		},
		{
			// Values from RFC 7616 erratum 4897; the printed example has the
			// wrong username hash and response.
			name:       "RFC 7616 SHA-512-256 userhash example",
			challenges: []string{`Digest realm="api@example.org", qop="auth", algorithm=SHA-512-256, nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS", charset=UTF-8, userhash=true`},
			auth:       &Auth{Type: DigestAuth, Username: "Jäsøn Doe", Password: "Secret, or not?"},
			method:     http.MethodGet,
			uri:        "/doe.json",
			cnonce:     "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v",
			want:       `Digest username="793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b", realm="api@example.org", nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", uri="/doe.json", algorithm=SHA-512-256, qop=auth, nc=00000001, cnonce="NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v", response="3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5", opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS", userhash=true`,
		},
		{
			// RFC 2069, section 2.4, prints response="e966c932…", which doesn't
			// match its own formula. This is the computed value.
			name:       "RFC 2069 without qop",
			challenges: []string{`Digest realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"`},
			auth:       &Auth{Type: DigestAuth, Username: "Mufasa", Password: "CircleOfLife"},
			method:     http.MethodGet,
			uri:        "/dir/index.html",
			want:       `Digest ` + rfc2617Fields + `, response="1949323746fe6a43ef61f9606e7febea", opaque="5ccc069c403ebaf9f0171e9517f40e41"`,
		},
		{
			name:       "MD5-sess",
			challenges: []string{strings.Replace(rfc2617Challenge, "Digest ", "Digest algorithm=MD5-sess, ", 1)},
			auth:       mufasa,
			method:     http.MethodGet,
			uri:        "/dir/index.html",
			cnonce:     "0a4f113b",
			want:       `Digest ` + rfc2617Fields + `, algorithm=MD5-sess, qop=auth, nc=00000001, cnonce="0a4f113b", response="8e3825c57e897f5a0dec6c2d4e5059d0", opaque="5ccc069c403ebaf9f0171e9517f40e41"`,
		},
		{
			name:       "SHA-256-sess",
			challenges: []string{strings.Replace(rfc2617Challenge, "Digest ", "Digest algorithm=SHA-256-sess, ", 1)},
			auth:       mufasa,
			method:     http.MethodGet,
			uri:        "/dir/index.html",
			cnonce:     "0a4f113b",
			want:       `Digest ` + rfc2617Fields + `, algorithm=SHA-256-sess, qop=auth, nc=00000001, cnonce="0a4f113b", response="b8822e12417cb7750f4e2b8515f0dcf25b7dd26993e80bee1426201446a7f59b", opaque="5ccc069c403ebaf9f0171e9517f40e41"`,
		},
		{
			name:       "auth-int hashes the body",
			challenges: []string{strings.Replace(rfc2617Challenge, `qop="auth,auth-int"`, `qop="auth-int"`, 1)},
			auth:       mufasa,
			method:     http.MethodPost,
			uri:        "/dir/index.html",
			body:       "hello",
			cnonce:     "0a4f113b",
			want:       `Digest ` + rfc2617Fields + `, qop=auth-int, nc=00000001, cnonce="0a4f113b", response="b3da9049011b9dafbd8fc28b2deecc0b", opaque="5ccc069c403ebaf9f0171e9517f40e41"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge, ok := findDigestChallenge(http.Header{"Www-Authenticate": tt.challenges})
			require.True(t, ok, "no supported challenge found")
			got := challenge.authorization(tt.auth, tt.method, tt.uri, []byte(tt.body), tt.cnonce)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFindDigestChallengeUnsupported(t *testing.T) {
	for _, header := range []string{
		`Basic realm="r"`,
		`Digest realm="r", nonce="n", algorithm=SHA-1`,
		`Digest realm="r", nonce="n", qop="auth-conf"`,
		`Negotiate abc==, Basic realm="r", Digest`,
	} {
		_, ok := findDigestChallenge(http.Header{"Www-Authenticate": {header}})
		require.False(t, ok, header)
	}
}

// TestFindDigestChallengeIsLinear guards against WWW-Authenticate values that
// made parsing quadratic in the header length. Each value here is 2 MiB;
// quadratic parsing took over 10s for that size.
func TestFindDigestChallengeIsLinear(t *testing.T) {
	words := strings.Repeat("x ", 1<<20)
	for _, header := range []string{"Digest " + words, "Digest " + words + "=v"} {
		start := time.Now()
		_, ok := findDigestChallenge(http.Header{"Www-Authenticate": {header}})
		require.False(t, ok)
		require.Less(t, time.Since(start), 2*time.Second)
	}
}

func TestCutChallenge(t *testing.T) {
	tests := []struct {
		in, scheme, rest string
		params           map[string]string
	}{
		{
			in:     ` Digest Realm="a \"b\", c\\d" ,qop="auth, auth-int",algorithm=MD5 , stale = true, Basic realm="x"`,
			scheme: "Digest",
			params: map[string]string{"realm": `a "b", c\d`, "qop": "auth, auth-int", "algorithm": "MD5", "stale": "true"},
			rest:   `Basic realm="x"`,
		},
		{
			in:     `Negotiate abc==, Digest realm="r"`,
			scheme: "Negotiate",
			params: map[string]string{"abc": "="},
			rest:   `Digest realm="r"`,
		},
		{
			in:     `Basic, Digest realm="r"`,
			scheme: "Basic",
			rest:   `Digest realm="r"`,
		},
		{
			in:     "Digest",
			scheme: "Digest",
		},
	}
	for _, tt := range tests {
		scheme, params, rest := cutChallenge(tt.in)
		require.Equal(t, tt.scheme, scheme, tt.in)
		require.Equal(t, tt.params, params, tt.in)
		require.Equal(t, tt.rest, rest, tt.in)
	}
}

func TestQuote(t *testing.T) {
	require.Equal(t, `"a \"b\" c\\d"`, quote(`a "b" c\d`))
	_, params, _ := cutChallenge("Digest u=" + quote(`a "b" c\d`))
	require.Equal(t, map[string]string{"u": `a "b" c\d`}, params)
}
