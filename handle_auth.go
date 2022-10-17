package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func (coauth2 *CaddyOauth2) HandleRequestAuth(w http.ResponseWriter, r *http.Request) (bool, error) {
	coauth2.logger.Debug("caddy_oauth2 handle oauth check url", zap.Any("URL", r.URL))
	if coauth2.isOAuthCallbackRequest(r) {
		err := coauth2.HandleOAuthCallback(w, r)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	cookies := r.Cookies()

	authCookie := getCookieByName(cookies, "COOKIEDATA")

	coauth2.logger.Debug("caddy_oauth2 handle req cookie data string", zap.String("authCookie COOKIEDATA", authCookie))

	if authCookie == "" {
		coauth2.logger.Debug("caddy_oauth2 handle oauth coauth2", zap.Any("coauth2", coauth2))
		oauthConfig := oauth2.Config{
			ClientID:     string(coauth2.ClientID),
			ClientSecret: string(coauth2.ClientSecret),
			Endpoint: oauth2.Endpoint{
				AuthURL:  string(coauth2.AuthURL),
				TokenURL: string(coauth2.TokenURL),
			},
			RedirectURL: string(coauth2.RedirectURL),
		}
		coauth2.logger.Debug("caddy_oauth2 handle oauth config", zap.Any("oauth config", oauthConfig))
		url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOnline)
		coauth2.logger.Debug("caddy_oauth2 handle redirect string", zap.String("url", url))
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		return true, nil
	}

	return false, nil
}

func (coauth2 *CaddyOauth2) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) error {
	coauth2.logger.Debug("caddy_oauth2 handle oauth coauth2 callback", zap.Any("coauth2", r.URL))

	oauthConfig := &oauth2.Config{
		ClientID:     string(coauth2.ClientID),
		ClientSecret: string(coauth2.ClientSecret),
		Endpoint: oauth2.Endpoint{
			AuthURL:  string(coauth2.AuthURL),
			TokenURL: string(coauth2.TokenURL),
		},
		RedirectURL: string(coauth2.RedirectURL),
	}

	code := r.URL.Query().Get("code")
	coauth2.logger.Debug("caddy_oauth2 handle oauth coauth2 callback code", zap.String("code", code))

	token, err := oauthConfig.Exchange(coauth2.ctx, code, oauth2.AccessTypeOnline)
	if err != nil {
		return err
	}
	coauth2.logger.Debug("caddy_oauth2 handle oauth coauth2 callback token", zap.Any("token", token))
	tj, _ := json.Marshal(token)
	etj := url.PathEscape(string(tj))
	dataCookie := &http.Cookie{
		Name:    "COOKIEDATA",
		Value:   etj,
		Path:    "/",
		Expires: token.Expiry,
	}
	coauth2.logger.Debug("caddy_oauth2 handle oauth coauth2 callback set cookie", zap.String("COOKIEDATA", etj))
	http.SetCookie(w, dataCookie)

	http.Redirect(w, r, "/", http.StatusFound)

	return nil
}

func (coauth2 *CaddyOauth2) isOAuthCallbackRequest(r *http.Request) bool {
	ozc := string(coauth2.RedirectURL)
	cu, _ := url.Parse(ozc)
	return cu.Path == r.URL.Path
}

func getCookieByName(cookies []*http.Cookie, name string) string {
	cookieLen := len(cookies)

	for i := 0; i < cookieLen; i++ {
		if cookies[i].Name == name {
			return cookies[i].Value
		}
	}
	return ""
}

