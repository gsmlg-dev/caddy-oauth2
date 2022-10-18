package caddy_oauth2

import (
	weakrand "math/rand"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"encoding/json"
	"net/url"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const DirectiveName = "caddy_oauth2"

func init() {
	httpcaddyfile.RegisterHandlerDirective(DirectiveName, parseCaddyfile)
	weakrand.Seed(time.Now().UnixNano())

	caddy.RegisterModule(CaddyOauth2{})

}

type CaddyOauth2 struct {
	AuthPath     caddyhttp.WeakString `json:"auth_path,omitempty"`
	ClientID     caddyhttp.WeakString `json:"client_id,omitempty"`
	ClientSecret caddyhttp.WeakString `json:"client_secret,omitempty"`
	AuthURL      caddyhttp.WeakString `json:"auth_url,omitempty"`
	TokenURL     caddyhttp.WeakString `json:"token_url,omitempty"`
	RedirectURL  caddyhttp.WeakString `json:"redirect_url,omitempty"`

	// config *oauth2.Config

	ctx    caddy.Context
	logger *zap.Logger
}

func (CaddyOauth2) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers." + DirectiveName,
		New: func() caddy.Module { return new(CaddyOauth2) },
	}
}

func (coauth2 *CaddyOauth2) Provision(ctx caddy.Context) error {
	coauth2.logger = ctx.Logger(coauth2)
	coauth2.ctx = ctx

	return nil
}

func (coauth2 *CaddyOauth2) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if coauth2.IsAuthPath(w, r) {
		return coauth2.HandleAuthPath(w, r)
	}
	if coauth2.IsOAuthCallbackRequest(w, r) {
		return coauth2.HandleOAuthCallback(w, r, next)
	}

	return next.ServeHTTP(w, r)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var coauth2 CaddyOauth2

	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "auth_path":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				coauth2.AuthPath = caddyhttp.WeakString(h.Val())
			case "client_id":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				coauth2.ClientID = caddyhttp.WeakString(h.Val())

			case "client_secret":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				coauth2.ClientSecret = caddyhttp.WeakString(h.Val())

			case "auth_url":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				coauth2.AuthURL = caddyhttp.WeakString(h.Val())

			case "token_url":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				coauth2.TokenURL = caddyhttp.WeakString(h.Val())

			case "redirect_url":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				coauth2.RedirectURL = caddyhttp.WeakString(h.Val())

			default:
				return nil, h.Errf("unknown subdirective '%s'", h.Val())
			}
		}
	}

	return &coauth2, nil
}

func (coauth2 *CaddyOauth2) IsAuthPath(w http.ResponseWriter, r *http.Request) bool {
	ozc := string(coauth2.AuthPath)
	cu, _ := url.Parse(ozc)
	return cu.Path == r.URL.Path
}

func (coauth2 *CaddyOauth2) HandleAuthPath(w http.ResponseWriter, r *http.Request) error {
	oauthConfig := oauth2.Config{
		ClientID:     string(coauth2.ClientID),
		ClientSecret: string(coauth2.ClientSecret),
		Endpoint: oauth2.Endpoint{
			AuthURL:  string(coauth2.AuthURL),
			TokenURL: string(coauth2.TokenURL),
		},
		RedirectURL: string(coauth2.RedirectURL),
	}
	url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOnline)
	coauth2.logger.Debug("caddy_oauth2 redirect to oauth2 server", zap.String("url", url))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	return nil
}

func (coauth2 *CaddyOauth2) IsOAuthCallbackRequest(w http.ResponseWriter, r *http.Request) bool {
	ozc := string(coauth2.RedirectURL)
	cu, _ := url.Parse(ozc)
	return cu.Path == r.URL.Path
}

func (coauth2 *CaddyOauth2) HandleOAuthCallback(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
	coauth2.logger.Debug("caddy_oauth2 handle oauth2 callback code", zap.String("code", code))

	token, err := oauthConfig.Exchange(coauth2.ctx, code, oauth2.AccessTypeOnline)
	if err != nil {
		return err
	}
	coauth2.logger.Debug("caddy_oauth2 handle oauth2 callback token", zap.Any("token", token))
	tj, err := json.Marshal(token)
	if err != nil {
		return err
	}

	coauth2.logger.Debug("caddy_oauth2 handle oauth2 callback token header", zap.ByteString("OAuth2 token json string", tj))
	r.Header.Add("oauth2-token", string(tj))

	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyOauth2)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyOauth2)(nil)
)
