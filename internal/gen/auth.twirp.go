// Code generated by protoc-gen-twirp v8.1.1, DO NOT EDIT.
// source: auth.proto

package protos

import context "context"
import fmt "fmt"
import http "net/http"
import ioutil "io/ioutil"
import json "encoding/json"
import strconv "strconv"
import strings "strings"

import protojson "google.golang.org/protobuf/encoding/protojson"
import proto "google.golang.org/protobuf/proto"
import twirp "github.com/twitchtv/twirp"
import ctxsetters "github.com/twitchtv/twirp/ctxsetters"

// Version compatibility assertion.
// If the constant is not defined in the package, that likely means
// the package needs to be updated to work with this generated code.
// See https://twitchtv.github.io/twirp/docs/version_matrix.html
const _ = twirp.TwirpPackageMinVersion_8_1_0

// ==============
// Auth Interface
// ==============

type Auth interface {
	Authenticate(context.Context, *AuthenticateReq) (*AuthenticateRes, error)

	Authorize(context.Context, *AuthorizeReq) (*AuthorizeRes, error)

	Logout(context.Context, *LogoutReq) (*LogoutRes, error)
}

// ====================
// Auth Protobuf Client
// ====================

type authProtobufClient struct {
	client      HTTPClient
	urls        [3]string
	interceptor twirp.Interceptor
	opts        twirp.ClientOptions
}

// NewAuthProtobufClient creates a Protobuf client that implements the Auth interface.
// It communicates using Protobuf and can be configured with a custom HTTPClient.
func NewAuthProtobufClient(baseURL string, client HTTPClient, opts ...twirp.ClientOption) Auth {
	if c, ok := client.(*http.Client); ok {
		client = withoutRedirects(c)
	}

	clientOpts := twirp.ClientOptions{}
	for _, o := range opts {
		o(&clientOpts)
	}

	// Using ReadOpt allows backwards and forwads compatibility with new options in the future
	literalURLs := false
	_ = clientOpts.ReadOpt("literalURLs", &literalURLs)
	var pathPrefix string
	if ok := clientOpts.ReadOpt("pathPrefix", &pathPrefix); !ok {
		pathPrefix = "/twirp" // default prefix
	}

	// Build method URLs: <baseURL>[<prefix>]/<package>.<Service>/<Method>
	serviceURL := sanitizeBaseURL(baseURL)
	serviceURL += baseServicePath(pathPrefix, "protos", "Auth")
	urls := [3]string{
		serviceURL + "Authenticate",
		serviceURL + "Authorize",
		serviceURL + "Logout",
	}

	return &authProtobufClient{
		client:      client,
		urls:        urls,
		interceptor: twirp.ChainInterceptors(clientOpts.Interceptors...),
		opts:        clientOpts,
	}
}

func (c *authProtobufClient) Authenticate(ctx context.Context, in *AuthenticateReq) (*AuthenticateRes, error) {
	ctx = ctxsetters.WithPackageName(ctx, "protos")
	ctx = ctxsetters.WithServiceName(ctx, "Auth")
	ctx = ctxsetters.WithMethodName(ctx, "Authenticate")
	caller := c.callAuthenticate
	if c.interceptor != nil {
		caller = func(ctx context.Context, req *AuthenticateReq) (*AuthenticateRes, error) {
			resp, err := c.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*AuthenticateReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*AuthenticateReq) when calling interceptor")
					}
					return c.callAuthenticate(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*AuthenticateRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*AuthenticateRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}
	return caller(ctx, in)
}

func (c *authProtobufClient) callAuthenticate(ctx context.Context, in *AuthenticateReq) (*AuthenticateRes, error) {
	out := new(AuthenticateRes)
	ctx, err := doProtobufRequest(ctx, c.client, c.opts.Hooks, c.urls[0], in, out)
	if err != nil {
		twerr, ok := err.(twirp.Error)
		if !ok {
			twerr = twirp.InternalErrorWith(err)
		}
		callClientError(ctx, c.opts.Hooks, twerr)
		return nil, err
	}

	callClientResponseReceived(ctx, c.opts.Hooks)

	return out, nil
}

func (c *authProtobufClient) Authorize(ctx context.Context, in *AuthorizeReq) (*AuthorizeRes, error) {
	ctx = ctxsetters.WithPackageName(ctx, "protos")
	ctx = ctxsetters.WithServiceName(ctx, "Auth")
	ctx = ctxsetters.WithMethodName(ctx, "Authorize")
	caller := c.callAuthorize
	if c.interceptor != nil {
		caller = func(ctx context.Context, req *AuthorizeReq) (*AuthorizeRes, error) {
			resp, err := c.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*AuthorizeReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*AuthorizeReq) when calling interceptor")
					}
					return c.callAuthorize(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*AuthorizeRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*AuthorizeRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}
	return caller(ctx, in)
}

func (c *authProtobufClient) callAuthorize(ctx context.Context, in *AuthorizeReq) (*AuthorizeRes, error) {
	out := new(AuthorizeRes)
	ctx, err := doProtobufRequest(ctx, c.client, c.opts.Hooks, c.urls[1], in, out)
	if err != nil {
		twerr, ok := err.(twirp.Error)
		if !ok {
			twerr = twirp.InternalErrorWith(err)
		}
		callClientError(ctx, c.opts.Hooks, twerr)
		return nil, err
	}

	callClientResponseReceived(ctx, c.opts.Hooks)

	return out, nil
}

func (c *authProtobufClient) Logout(ctx context.Context, in *LogoutReq) (*LogoutRes, error) {
	ctx = ctxsetters.WithPackageName(ctx, "protos")
	ctx = ctxsetters.WithServiceName(ctx, "Auth")
	ctx = ctxsetters.WithMethodName(ctx, "Logout")
	caller := c.callLogout
	if c.interceptor != nil {
		caller = func(ctx context.Context, req *LogoutReq) (*LogoutRes, error) {
			resp, err := c.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*LogoutReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*LogoutReq) when calling interceptor")
					}
					return c.callLogout(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*LogoutRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*LogoutRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}
	return caller(ctx, in)
}

func (c *authProtobufClient) callLogout(ctx context.Context, in *LogoutReq) (*LogoutRes, error) {
	out := new(LogoutRes)
	ctx, err := doProtobufRequest(ctx, c.client, c.opts.Hooks, c.urls[2], in, out)
	if err != nil {
		twerr, ok := err.(twirp.Error)
		if !ok {
			twerr = twirp.InternalErrorWith(err)
		}
		callClientError(ctx, c.opts.Hooks, twerr)
		return nil, err
	}

	callClientResponseReceived(ctx, c.opts.Hooks)

	return out, nil
}

// ================
// Auth JSON Client
// ================

type authJSONClient struct {
	client      HTTPClient
	urls        [3]string
	interceptor twirp.Interceptor
	opts        twirp.ClientOptions
}

// NewAuthJSONClient creates a JSON client that implements the Auth interface.
// It communicates using JSON and can be configured with a custom HTTPClient.
func NewAuthJSONClient(baseURL string, client HTTPClient, opts ...twirp.ClientOption) Auth {
	if c, ok := client.(*http.Client); ok {
		client = withoutRedirects(c)
	}

	clientOpts := twirp.ClientOptions{}
	for _, o := range opts {
		o(&clientOpts)
	}

	// Using ReadOpt allows backwards and forwads compatibility with new options in the future
	literalURLs := false
	_ = clientOpts.ReadOpt("literalURLs", &literalURLs)
	var pathPrefix string
	if ok := clientOpts.ReadOpt("pathPrefix", &pathPrefix); !ok {
		pathPrefix = "/twirp" // default prefix
	}

	// Build method URLs: <baseURL>[<prefix>]/<package>.<Service>/<Method>
	serviceURL := sanitizeBaseURL(baseURL)
	serviceURL += baseServicePath(pathPrefix, "protos", "Auth")
	urls := [3]string{
		serviceURL + "Authenticate",
		serviceURL + "Authorize",
		serviceURL + "Logout",
	}

	return &authJSONClient{
		client:      client,
		urls:        urls,
		interceptor: twirp.ChainInterceptors(clientOpts.Interceptors...),
		opts:        clientOpts,
	}
}

func (c *authJSONClient) Authenticate(ctx context.Context, in *AuthenticateReq) (*AuthenticateRes, error) {
	ctx = ctxsetters.WithPackageName(ctx, "protos")
	ctx = ctxsetters.WithServiceName(ctx, "Auth")
	ctx = ctxsetters.WithMethodName(ctx, "Authenticate")
	caller := c.callAuthenticate
	if c.interceptor != nil {
		caller = func(ctx context.Context, req *AuthenticateReq) (*AuthenticateRes, error) {
			resp, err := c.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*AuthenticateReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*AuthenticateReq) when calling interceptor")
					}
					return c.callAuthenticate(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*AuthenticateRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*AuthenticateRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}
	return caller(ctx, in)
}

func (c *authJSONClient) callAuthenticate(ctx context.Context, in *AuthenticateReq) (*AuthenticateRes, error) {
	out := new(AuthenticateRes)
	ctx, err := doJSONRequest(ctx, c.client, c.opts.Hooks, c.urls[0], in, out)
	if err != nil {
		twerr, ok := err.(twirp.Error)
		if !ok {
			twerr = twirp.InternalErrorWith(err)
		}
		callClientError(ctx, c.opts.Hooks, twerr)
		return nil, err
	}

	callClientResponseReceived(ctx, c.opts.Hooks)

	return out, nil
}

func (c *authJSONClient) Authorize(ctx context.Context, in *AuthorizeReq) (*AuthorizeRes, error) {
	ctx = ctxsetters.WithPackageName(ctx, "protos")
	ctx = ctxsetters.WithServiceName(ctx, "Auth")
	ctx = ctxsetters.WithMethodName(ctx, "Authorize")
	caller := c.callAuthorize
	if c.interceptor != nil {
		caller = func(ctx context.Context, req *AuthorizeReq) (*AuthorizeRes, error) {
			resp, err := c.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*AuthorizeReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*AuthorizeReq) when calling interceptor")
					}
					return c.callAuthorize(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*AuthorizeRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*AuthorizeRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}
	return caller(ctx, in)
}

func (c *authJSONClient) callAuthorize(ctx context.Context, in *AuthorizeReq) (*AuthorizeRes, error) {
	out := new(AuthorizeRes)
	ctx, err := doJSONRequest(ctx, c.client, c.opts.Hooks, c.urls[1], in, out)
	if err != nil {
		twerr, ok := err.(twirp.Error)
		if !ok {
			twerr = twirp.InternalErrorWith(err)
		}
		callClientError(ctx, c.opts.Hooks, twerr)
		return nil, err
	}

	callClientResponseReceived(ctx, c.opts.Hooks)

	return out, nil
}

func (c *authJSONClient) Logout(ctx context.Context, in *LogoutReq) (*LogoutRes, error) {
	ctx = ctxsetters.WithPackageName(ctx, "protos")
	ctx = ctxsetters.WithServiceName(ctx, "Auth")
	ctx = ctxsetters.WithMethodName(ctx, "Logout")
	caller := c.callLogout
	if c.interceptor != nil {
		caller = func(ctx context.Context, req *LogoutReq) (*LogoutRes, error) {
			resp, err := c.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*LogoutReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*LogoutReq) when calling interceptor")
					}
					return c.callLogout(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*LogoutRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*LogoutRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}
	return caller(ctx, in)
}

func (c *authJSONClient) callLogout(ctx context.Context, in *LogoutReq) (*LogoutRes, error) {
	out := new(LogoutRes)
	ctx, err := doJSONRequest(ctx, c.client, c.opts.Hooks, c.urls[2], in, out)
	if err != nil {
		twerr, ok := err.(twirp.Error)
		if !ok {
			twerr = twirp.InternalErrorWith(err)
		}
		callClientError(ctx, c.opts.Hooks, twerr)
		return nil, err
	}

	callClientResponseReceived(ctx, c.opts.Hooks)

	return out, nil
}

// ===================
// Auth Server Handler
// ===================

type authServer struct {
	Auth
	interceptor      twirp.Interceptor
	hooks            *twirp.ServerHooks
	pathPrefix       string // prefix for routing
	jsonSkipDefaults bool   // do not include unpopulated fields (default values) in the response
	jsonCamelCase    bool   // JSON fields are serialized as lowerCamelCase rather than keeping the original proto names
}

// NewAuthServer builds a TwirpServer that can be used as an http.Handler to handle
// HTTP requests that are routed to the right method in the provided svc implementation.
// The opts are twirp.ServerOption modifiers, for example twirp.WithServerHooks(hooks).
func NewAuthServer(svc Auth, opts ...interface{}) TwirpServer {
	serverOpts := newServerOpts(opts)

	// Using ReadOpt allows backwards and forwads compatibility with new options in the future
	jsonSkipDefaults := false
	_ = serverOpts.ReadOpt("jsonSkipDefaults", &jsonSkipDefaults)
	jsonCamelCase := false
	_ = serverOpts.ReadOpt("jsonCamelCase", &jsonCamelCase)
	var pathPrefix string
	if ok := serverOpts.ReadOpt("pathPrefix", &pathPrefix); !ok {
		pathPrefix = "/twirp" // default prefix
	}

	return &authServer{
		Auth:             svc,
		hooks:            serverOpts.Hooks,
		interceptor:      twirp.ChainInterceptors(serverOpts.Interceptors...),
		pathPrefix:       pathPrefix,
		jsonSkipDefaults: jsonSkipDefaults,
		jsonCamelCase:    jsonCamelCase,
	}
}

// writeError writes an HTTP response with a valid Twirp error format, and triggers hooks.
// If err is not a twirp.Error, it will get wrapped with twirp.InternalErrorWith(err)
func (s *authServer) writeError(ctx context.Context, resp http.ResponseWriter, err error) {
	writeError(ctx, resp, err, s.hooks)
}

// handleRequestBodyError is used to handle error when the twirp server cannot read request
func (s *authServer) handleRequestBodyError(ctx context.Context, resp http.ResponseWriter, msg string, err error) {
	if context.Canceled == ctx.Err() {
		s.writeError(ctx, resp, twirp.NewError(twirp.Canceled, "failed to read request: context canceled"))
		return
	}
	if context.DeadlineExceeded == ctx.Err() {
		s.writeError(ctx, resp, twirp.NewError(twirp.DeadlineExceeded, "failed to read request: deadline exceeded"))
		return
	}
	s.writeError(ctx, resp, twirp.WrapError(malformedRequestError(msg), err))
}

// AuthPathPrefix is a convenience constant that may identify URL paths.
// Should be used with caution, it only matches routes generated by Twirp Go clients,
// with the default "/twirp" prefix and default CamelCase service and method names.
// More info: https://twitchtv.github.io/twirp/docs/routing.html
const AuthPathPrefix = "/twirp/protos.Auth/"

func (s *authServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	ctx = ctxsetters.WithPackageName(ctx, "protos")
	ctx = ctxsetters.WithServiceName(ctx, "Auth")
	ctx = ctxsetters.WithResponseWriter(ctx, resp)

	var err error
	ctx, err = callRequestReceived(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	if req.Method != "POST" {
		msg := fmt.Sprintf("unsupported method %q (only POST is allowed)", req.Method)
		s.writeError(ctx, resp, badRouteError(msg, req.Method, req.URL.Path))
		return
	}

	// Verify path format: [<prefix>]/<package>.<Service>/<Method>
	prefix, pkgService, method := parseTwirpPath(req.URL.Path)
	if pkgService != "protos.Auth" {
		msg := fmt.Sprintf("no handler for path %q", req.URL.Path)
		s.writeError(ctx, resp, badRouteError(msg, req.Method, req.URL.Path))
		return
	}
	if prefix != s.pathPrefix {
		msg := fmt.Sprintf("invalid path prefix %q, expected %q, on path %q", prefix, s.pathPrefix, req.URL.Path)
		s.writeError(ctx, resp, badRouteError(msg, req.Method, req.URL.Path))
		return
	}

	switch method {
	case "Authenticate":
		s.serveAuthenticate(ctx, resp, req)
		return
	case "Authorize":
		s.serveAuthorize(ctx, resp, req)
		return
	case "Logout":
		s.serveLogout(ctx, resp, req)
		return
	default:
		msg := fmt.Sprintf("no handler for path %q", req.URL.Path)
		s.writeError(ctx, resp, badRouteError(msg, req.Method, req.URL.Path))
		return
	}
}

func (s *authServer) serveAuthenticate(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	header := req.Header.Get("Content-Type")
	i := strings.Index(header, ";")
	if i == -1 {
		i = len(header)
	}
	switch strings.TrimSpace(strings.ToLower(header[:i])) {
	case "application/json":
		s.serveAuthenticateJSON(ctx, resp, req)
	case "application/protobuf":
		s.serveAuthenticateProtobuf(ctx, resp, req)
	default:
		msg := fmt.Sprintf("unexpected Content-Type: %q", req.Header.Get("Content-Type"))
		twerr := badRouteError(msg, req.Method, req.URL.Path)
		s.writeError(ctx, resp, twerr)
	}
}

func (s *authServer) serveAuthenticateJSON(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	var err error
	ctx = ctxsetters.WithMethodName(ctx, "Authenticate")
	ctx, err = callRequestRouted(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	d := json.NewDecoder(req.Body)
	rawReqBody := json.RawMessage{}
	if err := d.Decode(&rawReqBody); err != nil {
		s.handleRequestBodyError(ctx, resp, "the json request could not be decoded", err)
		return
	}
	reqContent := new(AuthenticateReq)
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err = unmarshaler.Unmarshal(rawReqBody, reqContent); err != nil {
		s.handleRequestBodyError(ctx, resp, "the json request could not be decoded", err)
		return
	}

	handler := s.Auth.Authenticate
	if s.interceptor != nil {
		handler = func(ctx context.Context, req *AuthenticateReq) (*AuthenticateRes, error) {
			resp, err := s.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*AuthenticateReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*AuthenticateReq) when calling interceptor")
					}
					return s.Auth.Authenticate(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*AuthenticateRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*AuthenticateRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}

	// Call service method
	var respContent *AuthenticateRes
	func() {
		defer ensurePanicResponses(ctx, resp, s.hooks)
		respContent, err = handler(ctx, reqContent)
	}()

	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}
	if respContent == nil {
		s.writeError(ctx, resp, twirp.InternalError("received a nil *AuthenticateRes and nil error while calling Authenticate. nil responses are not supported"))
		return
	}

	ctx = callResponsePrepared(ctx, s.hooks)

	marshaler := &protojson.MarshalOptions{UseProtoNames: !s.jsonCamelCase, EmitUnpopulated: !s.jsonSkipDefaults}
	respBytes, err := marshaler.Marshal(respContent)
	if err != nil {
		s.writeError(ctx, resp, wrapInternal(err, "failed to marshal json response"))
		return
	}

	ctx = ctxsetters.WithStatusCode(ctx, http.StatusOK)
	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	resp.WriteHeader(http.StatusOK)

	if n, err := resp.Write(respBytes); err != nil {
		msg := fmt.Sprintf("failed to write response, %d of %d bytes written: %s", n, len(respBytes), err.Error())
		twerr := twirp.NewError(twirp.Unknown, msg)
		ctx = callError(ctx, s.hooks, twerr)
	}
	callResponseSent(ctx, s.hooks)
}

func (s *authServer) serveAuthenticateProtobuf(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	var err error
	ctx = ctxsetters.WithMethodName(ctx, "Authenticate")
	ctx, err = callRequestRouted(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	buf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		s.handleRequestBodyError(ctx, resp, "failed to read request body", err)
		return
	}
	reqContent := new(AuthenticateReq)
	if err = proto.Unmarshal(buf, reqContent); err != nil {
		s.writeError(ctx, resp, malformedRequestError("the protobuf request could not be decoded"))
		return
	}

	handler := s.Auth.Authenticate
	if s.interceptor != nil {
		handler = func(ctx context.Context, req *AuthenticateReq) (*AuthenticateRes, error) {
			resp, err := s.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*AuthenticateReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*AuthenticateReq) when calling interceptor")
					}
					return s.Auth.Authenticate(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*AuthenticateRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*AuthenticateRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}

	// Call service method
	var respContent *AuthenticateRes
	func() {
		defer ensurePanicResponses(ctx, resp, s.hooks)
		respContent, err = handler(ctx, reqContent)
	}()

	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}
	if respContent == nil {
		s.writeError(ctx, resp, twirp.InternalError("received a nil *AuthenticateRes and nil error while calling Authenticate. nil responses are not supported"))
		return
	}

	ctx = callResponsePrepared(ctx, s.hooks)

	respBytes, err := proto.Marshal(respContent)
	if err != nil {
		s.writeError(ctx, resp, wrapInternal(err, "failed to marshal proto response"))
		return
	}

	ctx = ctxsetters.WithStatusCode(ctx, http.StatusOK)
	resp.Header().Set("Content-Type", "application/protobuf")
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	resp.WriteHeader(http.StatusOK)
	if n, err := resp.Write(respBytes); err != nil {
		msg := fmt.Sprintf("failed to write response, %d of %d bytes written: %s", n, len(respBytes), err.Error())
		twerr := twirp.NewError(twirp.Unknown, msg)
		ctx = callError(ctx, s.hooks, twerr)
	}
	callResponseSent(ctx, s.hooks)
}

func (s *authServer) serveAuthorize(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	header := req.Header.Get("Content-Type")
	i := strings.Index(header, ";")
	if i == -1 {
		i = len(header)
	}
	switch strings.TrimSpace(strings.ToLower(header[:i])) {
	case "application/json":
		s.serveAuthorizeJSON(ctx, resp, req)
	case "application/protobuf":
		s.serveAuthorizeProtobuf(ctx, resp, req)
	default:
		msg := fmt.Sprintf("unexpected Content-Type: %q", req.Header.Get("Content-Type"))
		twerr := badRouteError(msg, req.Method, req.URL.Path)
		s.writeError(ctx, resp, twerr)
	}
}

func (s *authServer) serveAuthorizeJSON(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	var err error
	ctx = ctxsetters.WithMethodName(ctx, "Authorize")
	ctx, err = callRequestRouted(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	d := json.NewDecoder(req.Body)
	rawReqBody := json.RawMessage{}
	if err := d.Decode(&rawReqBody); err != nil {
		s.handleRequestBodyError(ctx, resp, "the json request could not be decoded", err)
		return
	}
	reqContent := new(AuthorizeReq)
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err = unmarshaler.Unmarshal(rawReqBody, reqContent); err != nil {
		s.handleRequestBodyError(ctx, resp, "the json request could not be decoded", err)
		return
	}

	handler := s.Auth.Authorize
	if s.interceptor != nil {
		handler = func(ctx context.Context, req *AuthorizeReq) (*AuthorizeRes, error) {
			resp, err := s.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*AuthorizeReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*AuthorizeReq) when calling interceptor")
					}
					return s.Auth.Authorize(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*AuthorizeRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*AuthorizeRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}

	// Call service method
	var respContent *AuthorizeRes
	func() {
		defer ensurePanicResponses(ctx, resp, s.hooks)
		respContent, err = handler(ctx, reqContent)
	}()

	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}
	if respContent == nil {
		s.writeError(ctx, resp, twirp.InternalError("received a nil *AuthorizeRes and nil error while calling Authorize. nil responses are not supported"))
		return
	}

	ctx = callResponsePrepared(ctx, s.hooks)

	marshaler := &protojson.MarshalOptions{UseProtoNames: !s.jsonCamelCase, EmitUnpopulated: !s.jsonSkipDefaults}
	respBytes, err := marshaler.Marshal(respContent)
	if err != nil {
		s.writeError(ctx, resp, wrapInternal(err, "failed to marshal json response"))
		return
	}

	ctx = ctxsetters.WithStatusCode(ctx, http.StatusOK)
	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	resp.WriteHeader(http.StatusOK)

	if n, err := resp.Write(respBytes); err != nil {
		msg := fmt.Sprintf("failed to write response, %d of %d bytes written: %s", n, len(respBytes), err.Error())
		twerr := twirp.NewError(twirp.Unknown, msg)
		ctx = callError(ctx, s.hooks, twerr)
	}
	callResponseSent(ctx, s.hooks)
}

func (s *authServer) serveAuthorizeProtobuf(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	var err error
	ctx = ctxsetters.WithMethodName(ctx, "Authorize")
	ctx, err = callRequestRouted(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	buf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		s.handleRequestBodyError(ctx, resp, "failed to read request body", err)
		return
	}
	reqContent := new(AuthorizeReq)
	if err = proto.Unmarshal(buf, reqContent); err != nil {
		s.writeError(ctx, resp, malformedRequestError("the protobuf request could not be decoded"))
		return
	}

	handler := s.Auth.Authorize
	if s.interceptor != nil {
		handler = func(ctx context.Context, req *AuthorizeReq) (*AuthorizeRes, error) {
			resp, err := s.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*AuthorizeReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*AuthorizeReq) when calling interceptor")
					}
					return s.Auth.Authorize(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*AuthorizeRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*AuthorizeRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}

	// Call service method
	var respContent *AuthorizeRes
	func() {
		defer ensurePanicResponses(ctx, resp, s.hooks)
		respContent, err = handler(ctx, reqContent)
	}()

	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}
	if respContent == nil {
		s.writeError(ctx, resp, twirp.InternalError("received a nil *AuthorizeRes and nil error while calling Authorize. nil responses are not supported"))
		return
	}

	ctx = callResponsePrepared(ctx, s.hooks)

	respBytes, err := proto.Marshal(respContent)
	if err != nil {
		s.writeError(ctx, resp, wrapInternal(err, "failed to marshal proto response"))
		return
	}

	ctx = ctxsetters.WithStatusCode(ctx, http.StatusOK)
	resp.Header().Set("Content-Type", "application/protobuf")
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	resp.WriteHeader(http.StatusOK)
	if n, err := resp.Write(respBytes); err != nil {
		msg := fmt.Sprintf("failed to write response, %d of %d bytes written: %s", n, len(respBytes), err.Error())
		twerr := twirp.NewError(twirp.Unknown, msg)
		ctx = callError(ctx, s.hooks, twerr)
	}
	callResponseSent(ctx, s.hooks)
}

func (s *authServer) serveLogout(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	header := req.Header.Get("Content-Type")
	i := strings.Index(header, ";")
	if i == -1 {
		i = len(header)
	}
	switch strings.TrimSpace(strings.ToLower(header[:i])) {
	case "application/json":
		s.serveLogoutJSON(ctx, resp, req)
	case "application/protobuf":
		s.serveLogoutProtobuf(ctx, resp, req)
	default:
		msg := fmt.Sprintf("unexpected Content-Type: %q", req.Header.Get("Content-Type"))
		twerr := badRouteError(msg, req.Method, req.URL.Path)
		s.writeError(ctx, resp, twerr)
	}
}

func (s *authServer) serveLogoutJSON(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	var err error
	ctx = ctxsetters.WithMethodName(ctx, "Logout")
	ctx, err = callRequestRouted(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	d := json.NewDecoder(req.Body)
	rawReqBody := json.RawMessage{}
	if err := d.Decode(&rawReqBody); err != nil {
		s.handleRequestBodyError(ctx, resp, "the json request could not be decoded", err)
		return
	}
	reqContent := new(LogoutReq)
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err = unmarshaler.Unmarshal(rawReqBody, reqContent); err != nil {
		s.handleRequestBodyError(ctx, resp, "the json request could not be decoded", err)
		return
	}

	handler := s.Auth.Logout
	if s.interceptor != nil {
		handler = func(ctx context.Context, req *LogoutReq) (*LogoutRes, error) {
			resp, err := s.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*LogoutReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*LogoutReq) when calling interceptor")
					}
					return s.Auth.Logout(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*LogoutRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*LogoutRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}

	// Call service method
	var respContent *LogoutRes
	func() {
		defer ensurePanicResponses(ctx, resp, s.hooks)
		respContent, err = handler(ctx, reqContent)
	}()

	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}
	if respContent == nil {
		s.writeError(ctx, resp, twirp.InternalError("received a nil *LogoutRes and nil error while calling Logout. nil responses are not supported"))
		return
	}

	ctx = callResponsePrepared(ctx, s.hooks)

	marshaler := &protojson.MarshalOptions{UseProtoNames: !s.jsonCamelCase, EmitUnpopulated: !s.jsonSkipDefaults}
	respBytes, err := marshaler.Marshal(respContent)
	if err != nil {
		s.writeError(ctx, resp, wrapInternal(err, "failed to marshal json response"))
		return
	}

	ctx = ctxsetters.WithStatusCode(ctx, http.StatusOK)
	resp.Header().Set("Content-Type", "application/json")
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	resp.WriteHeader(http.StatusOK)

	if n, err := resp.Write(respBytes); err != nil {
		msg := fmt.Sprintf("failed to write response, %d of %d bytes written: %s", n, len(respBytes), err.Error())
		twerr := twirp.NewError(twirp.Unknown, msg)
		ctx = callError(ctx, s.hooks, twerr)
	}
	callResponseSent(ctx, s.hooks)
}

func (s *authServer) serveLogoutProtobuf(ctx context.Context, resp http.ResponseWriter, req *http.Request) {
	var err error
	ctx = ctxsetters.WithMethodName(ctx, "Logout")
	ctx, err = callRequestRouted(ctx, s.hooks)
	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}

	buf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		s.handleRequestBodyError(ctx, resp, "failed to read request body", err)
		return
	}
	reqContent := new(LogoutReq)
	if err = proto.Unmarshal(buf, reqContent); err != nil {
		s.writeError(ctx, resp, malformedRequestError("the protobuf request could not be decoded"))
		return
	}

	handler := s.Auth.Logout
	if s.interceptor != nil {
		handler = func(ctx context.Context, req *LogoutReq) (*LogoutRes, error) {
			resp, err := s.interceptor(
				func(ctx context.Context, req interface{}) (interface{}, error) {
					typedReq, ok := req.(*LogoutReq)
					if !ok {
						return nil, twirp.InternalError("failed type assertion req.(*LogoutReq) when calling interceptor")
					}
					return s.Auth.Logout(ctx, typedReq)
				},
			)(ctx, req)
			if resp != nil {
				typedResp, ok := resp.(*LogoutRes)
				if !ok {
					return nil, twirp.InternalError("failed type assertion resp.(*LogoutRes) when calling interceptor")
				}
				return typedResp, err
			}
			return nil, err
		}
	}

	// Call service method
	var respContent *LogoutRes
	func() {
		defer ensurePanicResponses(ctx, resp, s.hooks)
		respContent, err = handler(ctx, reqContent)
	}()

	if err != nil {
		s.writeError(ctx, resp, err)
		return
	}
	if respContent == nil {
		s.writeError(ctx, resp, twirp.InternalError("received a nil *LogoutRes and nil error while calling Logout. nil responses are not supported"))
		return
	}

	ctx = callResponsePrepared(ctx, s.hooks)

	respBytes, err := proto.Marshal(respContent)
	if err != nil {
		s.writeError(ctx, resp, wrapInternal(err, "failed to marshal proto response"))
		return
	}

	ctx = ctxsetters.WithStatusCode(ctx, http.StatusOK)
	resp.Header().Set("Content-Type", "application/protobuf")
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	resp.WriteHeader(http.StatusOK)
	if n, err := resp.Write(respBytes); err != nil {
		msg := fmt.Sprintf("failed to write response, %d of %d bytes written: %s", n, len(respBytes), err.Error())
		twerr := twirp.NewError(twirp.Unknown, msg)
		ctx = callError(ctx, s.hooks, twerr)
	}
	callResponseSent(ctx, s.hooks)
}

func (s *authServer) ServiceDescriptor() ([]byte, int) {
	return twirpFileDescriptor1, 0
}

func (s *authServer) ProtocGenTwirpVersion() string {
	return "v8.1.1"
}

// PathPrefix returns the base service path, in the form: "/<prefix>/<package>.<Service>/"
// that is everything in a Twirp route except for the <Method>. This can be used for routing,
// for example to identify the requests that are targeted to this service in a mux.
func (s *authServer) PathPrefix() string {
	return baseServicePath(s.pathPrefix, "protos", "Auth")
}

var twirpFileDescriptor1 = []byte{
	// 383 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0x4f, 0x6b, 0xdb, 0x30,
	0x18, 0xc6, 0x71, 0x16, 0x32, 0xfb, 0x5d, 0x20, 0x4c, 0x64, 0xc4, 0x88, 0x6c, 0x18, 0xc1, 0x20,
	0x64, 0x60, 0x6f, 0xd9, 0x2d, 0x3b, 0x65, 0xb7, 0x6d, 0x39, 0x79, 0x6c, 0x87, 0xde, 0x94, 0x44,
	0x38, 0x86, 0x54, 0x4a, 0xfd, 0xca, 0x2d, 0xe9, 0xb1, 0xd7, 0x42, 0x2f, 0xfd, 0x68, 0xfd, 0x0a,
	0xfd, 0x20, 0x45, 0x52, 0xed, 0xfc, 0x69, 0x43, 0x7b, 0xb1, 0xad, 0xf7, 0x79, 0xf4, 0xd3, 0xf3,
	0xbe, 0x16, 0x00, 0x2f, 0xf5, 0x32, 0x5e, 0x17, 0x4a, 0x2b, 0xd2, 0xb2, 0x2f, 0xa4, 0xfd, 0x4c,
	0xa9, 0x6c, 0x25, 0x12, 0xbe, 0xce, 0x13, 0x2e, 0xa5, 0xd2, 0x5c, 0xe7, 0x4a, 0xa2, 0x73, 0x51,
	0x28, 0x51, 0x14, 0xee, 0x9b, 0x5d, 0x7b, 0xd0, 0x99, 0x94, 0x7a, 0x29, 0xa4, 0xce, 0xe7, 0x5c,
	0x8b, 0x54, 0x9c, 0x11, 0x0a, 0xbe, 0x71, 0x48, 0x7e, 0x2a, 0x42, 0x2f, 0xf2, 0x06, 0x41, 0x5a,
	0xaf, 0x8d, 0xb6, 0xe6, 0x88, 0x17, 0xaa, 0x58, 0x84, 0x0d, 0xa7, 0x55, 0x6b, 0xc2, 0xa0, 0x8d,
	0x9a, 0x6f, 0xa6, 0x2a, 0xcb, 0xc4, 0xe2, 0x97, 0x0c, 0xdf, 0x44, 0xde, 0xc0, 0x4f, 0xf7, 0x6a,
	0xa4, 0x0f, 0x81, 0x61, 0x4d, 0x32, 0x21, 0x75, 0xd8, 0xb4, 0x80, 0x6d, 0x81, 0xfd, 0x3d, 0x0c,
	0x83, 0xe4, 0x13, 0x00, 0x0a, 0xc4, 0x5c, 0xc9, 0x3f, 0x62, 0xf3, 0x18, 0x67, 0xa7, 0x42, 0x22,
	0x68, 0x9a, 0xfd, 0x36, 0xcc, 0xbb, 0x51, 0xdb, 0xb5, 0x85, 0xf1, 0x3f, 0x14, 0x45, 0x6a, 0x15,
	0x16, 0x43, 0xdb, 0x40, 0x55, 0x91, 0x5f, 0xda, 0xf6, 0x5e, 0x20, 0xb2, 0xaf, 0x7b, 0x7e, 0xac,
	0x4f, 0xf0, 0x8e, 0x9e, 0xf0, 0x05, 0x82, 0xa9, 0xca, 0x54, 0xa9, 0x5f, 0x83, 0xff, 0xbc, 0x35,
	0x23, 0x09, 0xe1, 0x2d, 0x96, 0xf3, 0xb9, 0x40, 0xb4, 0x4e, 0x3f, 0xad, 0x96, 0xa3, 0x9b, 0x06,
	0x34, 0x4d, 0x0c, 0x32, 0x73, 0x71, 0xaa, 0x99, 0x90, 0x5e, 0x15, 0xe0, 0xe0, 0xb7, 0xd1, 0x23,
	0x02, 0xb2, 0xe8, 0xea, 0xee, 0xfe, 0xb6, 0x41, 0xd9, 0x87, 0xe4, 0xfc, 0x5b, 0x62, 0x6e, 0x8b,
	0x7d, 0x54, 0x8e, 0xb1, 0x37, 0x24, 0xff, 0x21, 0xa8, 0x5b, 0x26, 0xdd, 0x5d, 0x4e, 0x35, 0x35,
	0xfa, 0x5c, 0x15, 0xd9, 0x47, 0x8b, 0xee, 0x31, 0xb2, 0x87, 0xb6, 0xb2, 0xe1, 0xfe, 0x86, 0x96,
	0xeb, 0x95, 0xbc, 0xaf, 0xb6, 0xd7, 0x83, 0xa2, 0x4f, 0x4a, 0xc8, 0xa8, 0xc5, 0x75, 0x59, 0xa7,
	0xc6, 0xad, 0xac, 0x36, 0xf6, 0x86, 0x3f, 0xe1, 0xc4, 0x8f, 0x7f, 0xb8, 0x1d, 0x33, 0x77, 0xcf,
	0xbf, 0x3f, 0x04, 0x00, 0x00, 0xff, 0xff, 0xac, 0x7b, 0xe7, 0xd8, 0xfc, 0x02, 0x00, 0x00,
}