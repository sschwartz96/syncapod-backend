// Package TestMain() located in auth_test.go
package grpc

import (
	"context"
	"testing"

	"github.com/sschwartz96/syncapod-backend/internal/protos"
	"google.golang.org/grpc"
)

func Test_PodcastGRPC(t *testing.T) {
	// setup pod client
	conn, err := grpc.DialContext(
		context.Background(), "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("failed to dial grpc bufnet: %v", err)
	}
	defer conn.Close()
	client := protos.NewPodClient(conn)

}
