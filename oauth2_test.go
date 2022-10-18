package caddy_oauth2

import (
	"testing"

	"golang.org/x/oauth2"
)

func TestOAuth2AuthCodeURL(t *testing.T) {
	oauthConfig := oauth2.Config{
		ClientID:     "test",
		ClientSecret: "fake",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://example.com/oauth2/authorize",
			TokenURL: "http://example.com/oauth2/token",
		},
		RedirectURL: "http://example.com/oauth2/redirect",
	}
	url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOnline)

	if url == "" {
		t.Errorf("Error: TestOAuth2AuthCodeURL %s", url)
	}
}
