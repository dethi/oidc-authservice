package authorizer

import (
	"net/http"
	"testing"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	input := []byte(`rules:
  foo.bar.io:
    groups:
      - baz@bar.com
      - beef@bar.com
  theo.von.io:
    groups:
      - ratking@von.io
      - plug@von.io`)

	ca := &configAuthorizer{}
	authzConfig, err := ca.parse(input)
	if err != nil {
		t.Errorf("error parsing config: %v", err)
	}
	t.Logf("loaded config: %v", *authzConfig)
}

func user(n string, groups ...string) *common.User {
	return &common.User{Name: n, Groups: groups}
}

func TestConfigAuthorizerMatching(t *testing.T) {
	type matchTCase struct {
		host  string
		match bool
		user  *common.User
	}

	tests := []struct {
		in       string
		behavior []matchTCase
	}{
		{
			in: "./testdata/authz.yaml",
			behavior: []matchTCase{
				// foo.bar.io tests
				{"foo.bar.io", false, user("none")},
				{"foo.bar.io", false, user("wrong", "wrong")},
				{"foo.bar.io", false, user("match1", "a@b.go")},
				{"foo.bar.io", false, user("match2", "ok@ok.go", "b@b.go")},
				// bar.io tests
				{"foo.bar.io", false, user("matching foo", "a@b.go")},
				{"foo.bar.io", false, user("match", "c@c.go")},
				// default unknown host behavior
				{"unknown host", true, user("no groups")},
			},
		},
		{
			in: "./testdata/allowAll.yaml",
			behavior: []matchTCase{
				{"happytohaveyou.io", true, user("no groups")},
				{"nothappy.io", false, user("no groups")},
				{"unknown host", true, user("no groups")},
			},
		},
		{
			in: "./testdata/allowNoneDefault.yaml",
			behavior: []matchTCase{
				{"unknown host", false, user("no groups")},
				{"nothappy.io", false, user("no groups")},
				{"ok.io", true, user("matches", "foo@bar.go")},
			},
		},
		{
			in: "./testdata/allowSingleGroupDefault.yaml",
			behavior: []matchTCase{
				{"unknown host", false, user("no groups")},
				{"unknown host", true, user("default match", "foo")},
				// doesn't match other matcher
				{"foo.bar.io", false, user("default doesnt match", "foo")},
				{"foo.bar.io", false, user("match", "baz@bar.go")},
			},
		},
		{
			in: "./testdata/allowWildcardHost.yaml",
			behavior: []matchTCase{
				// *.bar.io tests -> require regular-group
				{"foo.bar.io", false, user("nope1")},
				{"foo.bar.io", false, user("another1", "another-group")},
				{"foo.bar.io", true, user("user-match1", "regular-group")},
				{"anotherfoo.bar.io", true, user("user-match2", "regular-group")},
				{"yet.anotherfoo.bar.io", true, user("user-match3", "regular-group")},
				// admin.bar.io tests -> require restricted-group
				{"admin.bar.io", false, user("regular4", "regular-group")},
				{"admin.bar.io", true, user("restricted1", "restricted-group")},
				// bar.io tests and other host should fail because of default rule
				{"bar.io", false, user("another1", "another-group")},
				{"bar.io", false, user("regular1", "regular-group")},
				{"bar.io", false, user("restricted1", "restricted-group")},
				{"unknown host", false, user("nope1")},
			},
		},
	}

	for _, tcase := range tests {
		t.Run(tcase.in, func(t *testing.T) {
			ca, err := NewConfigAuthorizer(tcase.in)
			if err != nil {
				t.Fatal(err)
			}
			// t.Logf("created ca %+v", ca)
			for _, tc := range tcase.behavior {
				authed, reason, err := ca.Authorize(&http.Request{Host: tc.host}, tc.user)
				require.NoError(t, err, "unexpected error")
				require.Equalf(t, tc.match, authed, "%s", reason)
			}
		})
	}
}
