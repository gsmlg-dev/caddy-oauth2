# Caddy OAuth2

Simple OAuth2 Client as Caddy Module


```caddyfile
caddy_oauth2 {
	auth_path /oauth2/google
	client_id <client id>
	client_secret "<client secret>"
	auth_url "<auth url>"
	token_url "<token url>"
	redirect_url "<host>/oauth2/google/callback"
}
```

OAuth2 token will pass to backend in heaer `oauth2-token`


