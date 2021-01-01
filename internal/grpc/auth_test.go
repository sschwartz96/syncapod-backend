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
	"github.com/sschwartz96/syncapod-backend/internal/auth"
	"github.com/sschwartz96/syncapod-backend/internal/db"
	"github.com/sschwartz96/syncapod-backend/internal/podcast"
	"github.com/sschwartz96/syncapod-backend/internal/protos"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var (
	lis      *bufconn.Listener
	testDB   *pgxpool.Pool
	testUser = &db.UserRow{
		ID:    uuid.MustParse("b921c6e3-9cd0-4aed-9c4e-1d88ae20c777"),
		Email: "user@grpc.test", Username: "user_grpc_test",
		Birthdate:    time.Unix(0, 0).UTC(),
		PasswordHash: []byte("$2y$12$ndywn/c6wcB0oPv1ZRMLgeSQjTpXzOUCQy.5vdYvJxO9CS644i6Ce"),
		Created:      time.Unix(0, 0), LastSeen: time.Unix(0, 0),
	}
	// for podcast_test
	testPod     = &db.Podcast{ID: uuid.New(), Author: "Sam Schwartz", Description: "Syncapod Podcast", LinkURL: "https://syncapod.com/podcast", ImageURL: "http://syncapod.com/logo.png", Language: "en", Category: []int{1, 2, 3}, Explicit: "clean", RSSURL: "https://syncapod.com/podcast.rss"}
	testPod2    = &db.Podcast{ID: uuid.New(), Author: "Simon Schwartz", Description: "Syncapod Podcast 2", LinkURL: "https://syncapod.com/podcast2", ImageURL: "http://syncapod.com/logo.png", Language: "en", Category: []int{1, 2, 3}, Explicit: "explicit", RSSURL: "https://syncapod.com/podcast2.rss"}
	testEpi     = &db.Episode{ID: uuid.New(), PodcastID: testPod.ID, Title: "Test Episode", Episode: 123, PubDate: time.Unix(1000, 0)}
	testEpi2    = &db.Episode{ID: uuid.New(), PodcastID: testPod.ID, Title: "Test Episode 2", Episode: 124, PubDate: time.Unix(1001, 0)}
	testUserEpi = &db.UserEpisode{EpisodeID: testEpi.ID, UserID: testUser.ID, LastSeen: time.Now(), OffsetMillis: 123456, Played: false}
	testSub     = &db.Subscription{UserID: testUser.ID, PodcastID: testPod.ID, CompletedIDs: []uuid.UUID{testEpi.ID}, InProgressIDs: []uuid.UUID{testEpi2.ID}}
	testSub2    = &db.Subscription{UserID: testUser.ID, PodcastID: testPod2.ID, CompletedIDs: []uuid.UUID{}, InProgressIDs: []uuid.UUID{}}
)

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
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
			"postgres://postgres:secret@localhost:5432/postgres?sslmode=disable",
		)
		time.Sleep(time.Millisecond * 250)
	}

	// setup db
	err = setupDB()
	if err != nil {
		log.Fatalf("grpc.TestMain() error setting up database")
	}

	// setup grpc server
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	protos.RegisterAuthServer(s,
		NewAuthService(
			auth.NewAuthController(db.NewAuthStorePG(testDB),
				db.NewOAuthStorePG(testDB),
			),
		),
	)
	podCon, err := podcast.NewPodController(db.NewPodcastStore(testDB))
	if err != nil {
		log.Fatalf("grpc.TestMain() failed to create podController: %v", err)
	}
	protos.RegisterPodServer(s,
		NewPodcastService(podCon),
	)
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("gRPC test server exited with error: %v", err)
		}
	}()

	// run tests
	runCode := m.Run()

	err = cleanupDB()
	if err != nil {
		log.Println("grpc.auth_test, error cleaning up db:", err)
	}
	testDB.Close()

	os.Exit(runCode)
}

func setupDB() error {
	authStore := db.NewAuthStorePG(testDB)
	podStore := db.NewPodcastStore(testDB)
	err := authStore.InsertUser(context.Background(), testUser)
	if err != nil {
		return fmt.Errorf("failed to insert user: %v", err)
	}
	// for podcast_test
	if err = podStore.InsertPodcast(context.Background(), testPod); err != nil {
		return fmt.Errorf("failed to insert podcast: %v", err)
	}
	if err = podStore.InsertPodcast(context.Background(), testPod2); err != nil {
		return fmt.Errorf("failed to insert podcast: %v", err)
	}
	if err = podStore.InsertEpisode(context.Background(), testEpi); err != nil {
		return fmt.Errorf("failed to insert episode: %v", err)
	}
	if err = podStore.InsertEpisode(context.Background(), testEpi2); err != nil {
		return fmt.Errorf("failed to insert episode: %v", err)
	}
	if err = podStore.InsertSubscription(context.Background(), testSub); err != nil {
		return fmt.Errorf("failed to insert sub: %v", err)
	}
	if err = podStore.InsertSubscription(context.Background(), testSub2); err != nil {
		return fmt.Errorf("failed to insert sub: %v", err)
	}
	return nil
}

func cleanupDB() {
	testDB.Exec(context.Background(), "DELETE FROM Users")
	testDB.Exec(context.Background(), "DELETE FROM Sessions")
	testDB.Exec(context.Background(), "DELETE FROM Podcasts")
	testDB.Exec(context.Background(), "DELETE FROM Episodes")
	testDB.Exec(context.Background(), "DELETE FROM Subscriptions")
}

func TestAuthGRPC(t *testing.T) {
	// setup auth client
	conn, err := grpc.DialContext(
		context.Background(), "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("failed to dial grpc bufnet: %v", err)
	}
	defer conn.Close()
	client := protos.NewAuthClient(conn)

	// Authenticate
	autheRes, err := client.Authenticate(context.Background(),
		&protos.AuthenticateReq{Username: testUser.Username, Password: "password"},
	)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	require.NotEmpty(t, autheRes.SessionKey)
	seshKey := autheRes.SessionKey
	log.Println("got session key:", seshKey)

	// Authorization
	authoRes, err := client.Authorize(context.Background(),
		&protos.AuthorizeReq{SessionKey: seshKey},
	)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	require.NotEmpty(t, authoRes.User)
	log.Println("authorized user:", authoRes.User)

	// Logout
	logoutRes, err := client.Logout(context.Background(),
		&protos.LogoutReq{SessionKey: seshKey},
	)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}
	require.Equal(t, true, logoutRes.Success)
}
