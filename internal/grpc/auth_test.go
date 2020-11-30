package grpc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/sschwartz96/syncapod-backend/internal/db"
	"github.com/sschwartz96/syncapod-backend/internal/protos"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var (
	lis      *bufconn.Listener
	testDB   *pgxpool.Pool
	testUser = &db.UserRow{
		ID:           uuid.MustParse("b921c6e3-9cd0-4aed-9c4e-1d88ae20c777"),
		Email:        "user@grpc.test",
		Username:     "user_grpc_test",
		Birthdate:    time.Unix(0, 0).UTC(),
		PasswordHash: []byte("$2y$12$ndywn/c6wcB0oPv1ZRMLgeSQjTpXzOUCQy.5vdYvJxO9CS644i6Ce"),
		Created:      time.Unix(0, 0),
		LastSeen:     time.Unix(0, 0),
	}
)

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func createMockAuthClient() (authClient protos.AuthClient, cleanup func() error) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithInsecure(),
	)
	if err != nil {
		log.Fatalf("Failed to dial bufnet: %v", err)
	}
	client := protos.NewAuthClient(conn)
	return client, conn.Close
}

func TestMain(m *testing.M) {
	// connect stop after 5 seconds
	start := time.Now()
	fiveSec := time.Second * 5
	err := errors.New("start loop")
	for err != nil {
		if time.Since(start) > fiveSec {
			log.Fatal(`Could not connect to postgres\n
				Took longer than 5 seconds, maybe download postgres image`)
		}
		testDB, err = pgxpool.Connect(context.Background(),
			fmt.Sprintf(
				"postgres://postgres:secret@localhost:5432/postgres?sslmode=disable",
			),
		)
		time.Sleep(time.Millisecond * 250)
	}

	// setup db
	setupDB()

	// run tests
	runCode := m.Run()

	testDB.Close()

	os.Exit(runCode)
}

func setupDB() {
	authStore := db.NewAuthStorePG(testDB)
	authStore.InsertUser(context.Background(), testUser)
}

func TestAuthGRPC(t *testing.T) {

}
