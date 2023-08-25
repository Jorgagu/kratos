// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
	"github.com/ory/x/httpx"
)

type ProviderSteam struct {
	*ProviderGenericOIDC
}

func NewProviderSteam(
	config *Configuration,
	reg dependencies,
) *ProviderSteam {
	return &ProviderSteam{
		&ProviderGenericOIDC{
			config: config,
			reg:    reg,
		},
	}
}

func (s *ProviderSteam) Config() *Configuration {
	return s.config
}

func (s *ProviderSteam) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	return s.oauth2(ctx), nil
}

func (s *ProviderSteam) oauth2(ctx context.Context) *oauth2.Config {
	return &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://partner.steam-api.com/ISteamUserAuth/Authenticate",
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: s.config.Redir(s.reg.Config().OIDCRedirectURIBase(ctx)),
	}

}

func (s *ProviderSteam) Claims(ctx context.Context, exchange *oauth2.Token, query url.Values) (*Claims, error) {
	// larkClaim is defined in the https://open.feishu.cn/document/common-capabilities/sso/api/get-user-info
	type larkClaim struct {
		Sub          string `json:"sub"`
		Name         string `json:"name"`
		Picture      string `json:"picture"`
		OpenID       string `json:"open_id"`
		UnionID      string `json:"union_id"`
		EnName       string `json:"en_name"`
		TenantKey    string `json:"tenant_key"`
		AvatarURL    string `json:"avatar_url"`
		AvatarThumb  string `json:"avatar_thumb"`
		AvatarMiddle string `json:"avatar_middle"`
		AvatarBig    string `json:"avatar_big"`
		Email        string `json:"email"`
		UserID       string `json:"user_id"`
		Mobile       string `json:"mobile"`
	}
	var (
		client = s.reg.HTTPClient(ctx, httpx.ResilientClientDisallowInternalIPs())
		user   larkClaim
	)

	req, err := retryablehttp.NewRequest("GET", larkUserEndpoint, nil)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	exchange.SetAuthHeader(req.Request)
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}
	defer res.Body.Close()

	if err := logUpstreamError(s.reg.Logger(), res); err != nil {
		return nil, err
	}

	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	return &Claims{
		Issuer:      larkUserEndpoint,
		Subject:     user.OpenID,
		Name:        user.Name,
		Nickname:    user.Name,
		Picture:     user.AvatarURL,
		Email:       user.Email,
		PhoneNumber: user.Mobile,
	}, nil
}

func (s *ProviderSteam) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		//oauth2.SetAuthURLParam("openid.assoc_handle", "handle"),
		//oauth2.SetAuthURLParam("openid.signed", signed),
		//oauth2.SetAuthURLParam("openid.sig", sig),
		//oauth2.SetAuthURLParam("openid.ns", "http://specs.openid.net/auth/2.0"),
		//oauth2.SetAuthURLParam("openid.op_endpoint", endpoint),
		//oauth2.SetAuthURLParam("openid.claimed_id", claimedId),
		//oauth2.SetAuthURLParam("openid.identity", identity),
		//oauth2.SetAuthURLParam("openid.return_to", returnTo),
		//oauth2.SetAuthURLParam("openid.response_nonce", responseNonce),
		//oauth2.SetAuthURLParam("openid.invalidate_handle", invalidateHandle),
		//oauth2.SetAuthURLParam("openid.mode", "check_authentication"),
	}
}
