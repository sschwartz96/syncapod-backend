package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/google/uuid"
	"github.com/sschwartz96/syncapod-backend/internal/auth"
)

// OauthHandler handles authorization and authentication to oauth clients
type OauthHandler struct {
	authController auth.Auth
	loginTemplate  *template.Template
	authTemplate   *template.Template
	// only used for alexa, need these in database if suppport more than one client
	clientID     string
	clientSecret string
}

// CreateOauthHandler just intantiates an OauthHandler
func CreateOauthHandler(authController auth.Auth, clientID, clientSecret string) (*OauthHandler, error) {
	loginT, err := template.ParseFiles("templates/oauth/login.gohtml")
	authT, err := template.ParseFiles("templates/oauth/auth.gohtml")
	if err != nil {
		return nil, err
	}

	return &OauthHandler{
		authController: authController,
		loginTemplate:  loginT,
		authTemplate:   authT,
		clientID:       clientID,
		clientSecret:   clientSecret,
	}, nil
}

func (h *OauthHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	// path: /oauth/*
	var head string
	head, req.URL.Path = ShiftPath(req.URL.Path)
	switch head {
	case "login":
		h.Login(res, req)
	case "authorize":
		h.Authorize(res, req)
	case "token":
		h.Token(res, req)
	}
}

// Post hanldes all post request at the oauth endpoint
func (h *OauthHandler) Post(res http.ResponseWriter, req *http.Request) {
	var head string
	head, req.URL.Path = ShiftPath(req.URL.Path)
	// path: /oauth/*
	switch head {
	case "login":
		h.Login(res, req)
	case "authorize":
		h.Authorize(res, req)
	case "token":
		h.Token(res, req)
	}
}

// Login handles the post and get request of a login page
func (h *OauthHandler) Login(res http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		h.loginTemplate.Execute(res, true)
		return
	}
	err := req.ParseForm()
	if err != nil {
		fmt.Println("couldn't parse post values: ", err)
		h.loginTemplate.Execute(res, true)
		return
	}

	username := req.FormValue("uname")
	password := req.FormValue("pass")

	_, sesh, err := h.authController.Login(req.Context(), username, password, req.UserAgent())
	if err != nil {
		h.loginTemplate.Execute(res, true)
		return
	}

	req.Method = http.MethodGet

	values := url.Values{}

	values.Add("sesh_key", sesh.ID.String())
	values.Add("client_id", req.URL.Query().Get("client_id"))
	values.Add("redirect_uri", req.URL.Query().Get("redirect_uri"))
	values.Add("state", req.URL.Query().Get("state"))

	http.Redirect(res, req, "/oauth/authorize"+"?"+values.Encode(), http.StatusSeeOther)
}

// Authorize takes a session(access) token and validates it and sents back user info
func (h *OauthHandler) Authorize(res http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		//	key := strings.TrimSpace(req.URL.Query().Get("sesh_key"))
		//	seshID, err := uuid.Parse(key)
		//	if err != nil {
		//		fmt.Println("invalid seshID: ", err)
		//		http.Redirect(res, req, "/oauth/login", http.StatusSeeOther)
		//	}
		//	_, err = h.authController.Authorize(req.Context(), seshID)
		//	if err != nil {
		//		fmt.Println("couldn't not validate, redirecting to login page: ", err)
		//		http.Redirect(res, req, "/oauth/login", http.StatusSeeOther)
		//		return
		//	}
		err := h.authTemplate.Execute(res, nil)
		if err != nil {
			fmt.Println("OauthHandler.Authorize() error executing template: %v", err)
		}
		return
	}

	// get session key, validate and get user info
	seshKey := strings.TrimSpace(req.URL.Query().Get("sesh_key"))
	seshID, err := uuid.Parse(seshKey)
	if err != nil {
		fmt.Println("invalid key: ", err)
		http.Redirect(res, req, "/oauth/login", http.StatusSeeOther)
		return
	}
	user, err := h.authController.Authorize(req.Context(), seshID)
	if err != nil {
		fmt.Println("couldn't not validate, redirecting to login page: ", err)
		http.Redirect(res, req, "/oauth/login", http.StatusSeeOther)
		return
	}

	// create auth code
	clientID := strings.TrimSpace(req.URL.Query().Get("client_id"))
	authCode, err := h.authController.CreateAuthCode(req.Context(), user.ID, clientID)
	if err != nil {
		//TODO: handle this error properly
		fmt.Printf("error creating oauth authorization code: %v\n", err)
	}

	// setup redirect url
	redirectURI := strings.TrimSpace(req.URL.Query().Get("redirect_uri"))

	// add query params
	values := url.Values{}
	values.Add("state", req.URL.Query().Get("state"))
	values.Add("code", authCode.Code)

	// redirect
	fmt.Println("auth: redirecting to: ", redirectURI+"?"+values.Encode())
	http.Redirect(res, req, redirectURI+"?"+values.Encode(), http.StatusSeeOther)
}

// Token handles authenticating the oauth client with the given token
func (h *OauthHandler) Token(res http.ResponseWriter, req *http.Request) {
	// authenticate client
	id, sec, ok := req.BasicAuth()
	if !ok {
		fmt.Println("not using basic authentication?")
		return
	}
	fmt.Printf("id: %v & secret: %v\n", id, sec)
	if id != h.clientID || sec != h.clientSecret {
		fmt.Println("incorrect credentials")
		return
	}

	// ^^^^^^^^^^ client is authenticated after above ^^^^^^^^^^
	var queryCode string
	// find grant type: refresh_token or authorization_code
	grantType := req.FormValue("grant_type")
	if strings.ToLower(grantType) == "refresh_token" {
		refreshToken := req.FormValue("refresh_token")
		accessToken, err := h.authController.ValidateRefreshToken(req.Context(), refreshToken)
		if err != nil {
			fmt.Println("couldn't find token based on refresh: ", err)
			http.Redirect(res, req, "/oauth/login", http.StatusSeeOther)
			//TODO: fail gracefully??
			return
		}
		queryCode = auth.EncodeKey(accessToken.AuthCode)
	} else {
		queryCode = req.FormValue("code")
	}

	// validate auth code
	authCode, err := h.authController.ValidateAuthCode(req.Context(), queryCode)
	if err != nil {
		fmt.Println("couldn't find auth code: ", err)
		http.Redirect(res, req, "/oauth/login", http.StatusSeeOther)
		// TODO: send more appropriate error response
		return
	}

	// create access token
	token, err := h.authController.CreateAccessToken(req.Context(), authCode)
	if err != nil {
		fmt.Println("error oauth handler(Token), could not create access token:", err)
		// TODO: send error message back
		http.Redirect(res, req, "/oauth/login", http.StatusSeeOther)
		return
	}

	// setup json
	type tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	tRes := &tokenResponse{
		AccessToken:  auth.EncodeKey(token.Code),
		RefreshToken: auth.EncodeKey(token.RefreshToken),
		ExpiresIn:    3600,
	}

	// marshal data and send off
	json, _ := json.Marshal(&tRes)
	res.Header().Set("Content-Type", "application/json")
	res.Write(json)
}
