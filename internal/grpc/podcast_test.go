// Package TestMain() located in auth_test.go
package grpc

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sschwartz96/syncapod-backend/internal/db"
	"github.com/sschwartz96/syncapod-backend/internal/protos"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var (
	// for podcast_test
	testPod     = &db.Podcast{ID: uuid.New(), Author: "Sam Schwartz", Description: "Syncapod Podcast", LinkURL: "https://syncapod.com/podcast", ImageURL: "http://syncapod.com/logo.png", Language: "en", Category: []int{1, 2, 3}, Explicit: "clean", RSSURL: "https://syncapod.com/podcast.rss"}
	testPod2    = &db.Podcast{ID: uuid.New(), Author: "Simon Schwartz", Description: "Syncapod Podcast 2", LinkURL: "https://syncapod.com/podcast2", ImageURL: "http://syncapod.com/logo.png", Language: "en", Category: []int{1, 2, 3}, Explicit: "explicit", RSSURL: "https://syncapod.com/podcast2.rss"}
	testEpi     = &db.Episode{ID: uuid.New(), PodcastID: testPod.ID, Title: "Test Episode", Episode: 123, PubDate: time.Unix(1000, 0)}
	testEpi2    = &db.Episode{ID: uuid.New(), PodcastID: testPod.ID, Title: "Test Episode 2", Episode: 124, PubDate: time.Unix(1001, 0)}
	testUserEpi = &db.UserEpisode{EpisodeID: testEpi.ID, UserID: testUser.ID, LastSeen: time.Now(), OffsetMillis: 123456, Played: false}
	testSub     = &db.Subscription{UserID: testUser.ID, PodcastID: testPod.ID, CompletedIDs: []uuid.UUID{testEpi.ID}, InProgressIDs: []uuid.UUID{testEpi2.ID}}
	testSub2    = &db.Subscription{UserID: testUser.ID, PodcastID: testPod2.ID, CompletedIDs: []uuid.UUID{}, InProgressIDs: []uuid.UUID{}}
	testSesh    = &db.SessionRow{ID: uuid.New(), UserID: testUser.ID, LoginTime: time.Now(), LastSeenTime: time.Now(), Expires: time.Now().Add(time.Hour), UserAgent: "testUserAgent"}
)

func setupPodDB() error {
	// for podcast_test
	var err error
	podStore := db.NewPodcastStore(dbpg)
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
	if err = podStore.UpsertUserEpisode(context.Background(), testUserEpi); err != nil {
		return fmt.Errorf("failed to insert user episode: %v", err)
	}
	// insert user session to mimic user already authenticated
	authStore := db.NewAuthStorePG(dbpg)
	if err = authStore.InsertSession(context.Background(), testSesh); err != nil {
		return fmt.Errorf("failed to insert user session: %v", err)
	}
	return nil
}

func Test_PodcastGRPC(t *testing.T) {
	// add metadata for authorization
	ctx := metadata.AppendToOutgoingContext(context.Background(), "token", testSesh.ID.String())

	// setup pod client
	conn, err := grpc.DialContext(
		ctx, "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("failed to dial grpc bufnet: %v", err)
	}
	defer conn.Close()
	client := protos.NewPodClient(conn)

	// GetPodcast
	pod, err := client.GetPodcast(ctx, &protos.GetPodReq{Id: testPod.ID.String()})
	if err != nil {
		log.Panicln("error: ", err)
	}
	require.Equal(t, nil, err)
	require.NotNil(t, pod)

	// GetEpisodes
	epis, err := client.GetEpisodes(ctx,
		&protos.GetEpiReq{
			Id:    testPod.ID.String(),
			Start: 0,
			End:   2,
		},
	)
	require.Equal(t, nil, err)
	require.Equal(t, 2, len(epis.Episodes))
	require.Equal(t, convertEpiFromDB(testEpi2), epis.Episodes[0])
	require.Equal(t, convertEpiFromDB(testEpi), epis.Episodes[1])

	// GetUserEpisode
	userEpi, err := client.GetUserEpisode(ctx,
		&protos.GetUserEpiReq{EpiID: testEpi.ID.String()})
	if err != nil {
		log.Println(err)
	}
	require.Equal(t, nil, err)
	require.NotEqual(t, nil, userEpi)

	// UpsertUserEpisode
	userEpi.Offset = 9999
	res, err := client.UpsertUserEpisode(ctx, userEpi)
	if err != nil {
		log.Println("userepisode:", err)
	}
	require.Equal(t, nil, err)
	require.NotEqual(t, nil, res)

	// GetSubscriptions
	subs, err := client.GetSubscriptions(ctx, &protos.GetSubReq{})
	require.Equal(t, nil, err)
	require.NotEmpty(t, subs.Subscriptions)

	// GetUserLastPlayed
	lastPlayRes, err := client.GetUserLastPlayed(ctx, &protos.GetUserLastPlayedReq{})
	require.Equal(t, nil, err)
	require.NotEmpty(t, lastPlayRes.Episode)
	require.NotEmpty(t, lastPlayRes.Podcast)
	require.NotEmpty(t, lastPlayRes.Millis)
}
