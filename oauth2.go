package oauth2

import (
	weakrand "math/rand"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.uber.org/zap"
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
	done, e := coauth2.HandleRequestAuth(w, r)
	if e != nil {
		return e
	}
	if done {
		return nil
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

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyOauth2)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyOauth2)(nil)
)
