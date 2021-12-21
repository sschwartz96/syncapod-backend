package twirp

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/google/uuid"
	"github.com/sschwartz96/syncapod-backend/internal/auth"
	"github.com/sschwartz96/syncapod-backend/internal/db"
	protos "github.com/sschwartz96/syncapod-backend/internal/gen"
	"github.com/twitchtv/twirp"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	authTokenKey = "Auth_Token"
	userIDKey    = "User_ID"
)

// Server is truly needed for its Intercept method which authenticates users before accessing services, but also useful to have all the grpc server boilerplate contained within NewServer function
type Server struct {
	authC    *auth.AuthController
	services []TwirpService
}

type TwirpService struct {
	name        string
	twirpServer protos.TwirpServer
}

func NewServer(a *autocert.Manager, aC *auth.AuthController, aS protos.Auth, pS protos.Pod, adminS protos.Admin) *Server {
	s := &Server{authC: aC}
	twirpServices := []TwirpService{
		{
			name: "admin",
			twirpServer: protos.NewAdminServer(
				adminS,
				twirp.WithServerPathPrefix("/rpc/admin"),
				twirp.WithServerInterceptors(s.authIntercept()),
				// twirp.WithServerHooks(
				// &twirp.ServerHooks{
				// 	RequestReceived: s.authorizeHook,
				// },
				// ),
			),
		},
		{
			name: "auth",
			twirpServer: protos.NewAuthServer(
				aS,
				twirp.WithServerPathPrefix("/rpc/auth"),
				twirp.WithServerInterceptors(s.authIntercept()),
				// twirp.WithServerHooks(
				// 	&twirp.ServerHooks{
				// 		RequestReceived: s.authorizeHook,
				// 	},
				// ),
			),
		},
		{
			name: "podcast",
			twirpServer: protos.NewPodServer(
				pS,
				twirp.WithServerPathPrefix("/rpc/podcast"),
				twirp.WithServerInterceptors(s.authIntercept()),
				// twirp.WithServerHooks(
				// 	&twirp.ServerHooks{
				// 		RequestReceived: s.authorizeHook,
				// 	},
				// ),
			),
		},
	}
	s.services = twirpServices
	return s
}

// could use this instead of hooks?
func (s *Server) authIntercept() twirp.Interceptor {
	return func(next twirp.Method) twirp.Method {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			// get the method name
			methodName, ok := twirp.MethodName(ctx)
			if !ok {
				return nil, twirp.NotFound.Error("Auth Intercept, Method Not Found")
			}
			// if Authenticate method then allow the method to proceed
			if methodName == "Authenticate" {
				return next(ctx, req)
			}

			// check for header and auth token
			header, ok := twirp.HTTPRequestHeaders(ctx)
			if !ok {
				return nil, twirp.NotFound.Error("Auth Intercept, HTTP Header Not Present")
			}

			authTokenString := header.Get(authTokenKey)
			authToken, err := uuid.Parse(authTokenString)
			if err != nil {
				return ctx, twirp.Unauthenticated.Error("")
			}
			user, err := s.authC.Authorize(ctx, authToken)
			if err != nil {
				return ctx, twirp.Unauthenticated.Error("")
			}
			ctx = context.WithValue(ctx, twirpContextKey{}, twirpContextValue{
				authToken: authToken,
				user:      user,
			})
			return next(ctx, req)
		}
	}
}

// func (s *Server) authorizeHook(ctx context.Context) (context.Context, error) {
// 	authTokenInterface := ctx.Value(twirpContextKey{})
// 	if authTokenInterface == nil {
// 		return ctx, twirp.Unauthenticated.Error("")
// 	}
// 	authTokenString, ok := authTokenInterface.(string)
// 	if !ok {
// 		return ctx, twirp.Unauthenticated.Error("")
// 	}
// 	authToken, err := uuid.Parse(authTokenString)
// 	if err != nil {
// 		return ctx, twirp.Unauthenticated.Error("")
// 	}
// 	user, err := s.authC.Authorize(ctx, authToken)
// 	if err != nil {
// 		return ctx, twirp.Unauthenticated.Error("")
// 	}
// 	ctx = context.WithValue(ctx, twirpContextKey{}, twirpContextValue{
// 		authToken: authToken,
// 		user:      user,
// 	})
// 	return ctx, nil
// }

// // authorizeMiddleware authorizes the users rpc request by checking the AuthToken header
// // if successful context is updated with basic user information
// func (s *Server) authorizeMiddleware(handler http.Handler) http.HandlerFunc {
// 	return func(res http.ResponseWriter, req *http.Request) {
// 		// get the auth token from http header
// 		authToken := req.Header.Get(authTokenKey)
// 		// create new req context with auth token value
// 		newCtx := context.WithValue(req.Context(), twirpContextKey{}, authToken)
// 		// call original hander's ServeHTTP function
// 		handler.ServeHTTP(res, req.WithContext(newCtx))
// 	}
// }

type twirpContextKey struct{}

type twirpContextValue struct {
	authToken uuid.UUID
	user      *db.UserRow
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	for _, service := range s.services {
		// mux.Handle(service.twirpServer.PathPrefix(), s.authorizeMiddleware(service.twirpServer))
		mux.Handle(service.twirpServer.PathPrefix(), service.twirpServer)
	}
	return http.ListenAndServe(":8081", mux)
}

func getCredsOpt(a *autocert.Manager) grpc.ServerOption {
	if a != nil {
		tlsConfig := &tls.Config{GetCertificate: a.GetCertificate}
		return grpc.Creds(
			credentials.NewTLS(
				tlsConfig,
			),
		)
	}
	return grpc.EmptyServerOption{}
}
