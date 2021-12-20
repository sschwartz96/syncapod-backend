package twirp

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/google/uuid"
	"github.com/sschwartz96/syncapod-backend/internal/auth"
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
		TwirpService{
			name: "auth",
			twirpServer: protos.NewAdminServer(
				adminS,
				twirp.WithServerPathPrefix(""),
				twirp.WithServerHooks(
					&twirp.ServerHooks{
						RequestReceived: s.authorizeHook,
					},
				),
			),
		},
	}
	return s
}

func (s *Server) authorizeHook(ctx context.Context) (context.Context, error) {
	//TODO: do I even need to run this hook since the authorizeMiddleware function
	//      takes care of authorization and inserting the user id into the context
	return ctx, nil
}

// authorizeMiddleware authorizes the users rpc request by checking the AUTH_TOKEN header
// if successful context is updated with basic user information
func (s *Server) authorizeMiddleware(handler http.Handler) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		authToken := req.Header.Get(authTokenKey)
		authTokenUUID, err := uuid.Parse(authToken)
		if err != nil {
			sendAuthorizedJSON(res)
			return
		}

		user, err := s.authC.Authorize(req.Context(), authTokenUUID)
		if err != nil {
			sendAuthorizedJSON(res)
			return
		}
		newCtx := context.WithValue(req.Context(), userIDKey, user.ID)
		handler.ServeHTTP(res, req.WithContext(newCtx))
	}
}

func sendAuthorizedJSON(res http.ResponseWriter) {
	res.WriteHeader(http.StatusUnauthorized)
	res.Header().Set("Content-Type", "application/json")
	res.Write([]byte("{\"message\": \"unauthorized\"}"))
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	for _, service := range s.services {
		mux.Handle("/rpc/"+service.name, s.authorizeMiddleware(service.twirpServer))
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
