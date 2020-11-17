package db

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var (
	testPod     = &Podcast{ID: uuid.New(), Author: "Sam Schwartz", Description: "Syncapod Podcast", LinkURL: "https://syncapod.com/podcast", ImageURL: "http://syncapod.com/logo.png", Language: "en", Category: []int{1, 2, 3}, Explicit: "clean", RSSURL: "https://syncapod.com/podcast.rss"}
	testEpi     = &Episode{ID: uuid.New(), PodcastID: testPod.ID, Title: "Test Episode", Episode: 123}
	testUser    = &UserRow{ID: uuid.New(), Username: "dbTestUser", PasswordHash: []byte("shouldbehash")}
	testUserEpi = &UserEpisode{ID: uuid.New(), EpisodeID: testEpi.ID, UserID: testUser.ID, LastSeen: time.Now(), Offset: 123456, Played: false}
)

func setupPodcastDB() {
	podStore := NewPodcastStore(testDB)
	authStore := NewAuthStorePG(testDB)
	err := podStore.InsertPodcast(context.Background(), testPod)
	if err != nil {
		log.Fatalf("db.setupPodcastDB() error: %v", err)
	}
	err = podStore.InsertEpisode(context.Background(), testEpi)
	if err != nil {
		log.Fatalf("db.setupPodcastDB() error: %v", err)
	}
	err = authStore.InsertUser(context.Background(), testUser)
	if err != nil {
		log.Fatalf("db.setupPodcastDB() error: %v", err)
	}
	err = podStore.UpsertUserEpisode(context.Background(), testUserEpi)
	if err != nil {
		log.Fatalf("db.setupPodcastDB() error: %v", err)
	}
}

func Test_InsertPodcast(t *testing.T) {
	podStore := NewPodcastStore(testDB)
	pod := &Podcast{ID: uuid.New(), Author: "Sam Schwartz", Description: "Test Insert Podcast", LinkURL: "https://syncapod.com/podcast", ImageURL: "http://syncapod.com/logo.png", Language: "en", Category: []int{1, 2, 3}, Explicit: "clean", RSSURL: "https://syncapod.com/podcast_test.rss"}
	err := podStore.InsertPodcast(context.Background(), pod)
	if err != nil {
		t.Fatalf("Test_InsertPodcast() error: %v", err)
	}
}

func Test_FindEpisodeNumber(t *testing.T) {
	podStore := NewPodcastStore(testDB)

	epiFound, err := podStore.FindEpisodeNumber(context.Background(), testEpi.PodcastID, 0, 123)
	if err != nil {
		t.Fatalf("Test_FindEpisodeNumber() error finding episode: %v", err)
	}
	require.NotNil(t, *epiFound)
}

func Test_SearchPodcasts(t *testing.T) {
	podStore := NewPodcastStore(testDB)
	pod := &Podcast{ID: uuid.New(), Author: "Sam Schwartz", Description: "PostgreSQL Search Test", LinkURL: "https://syncapod.com/podcast", ImageURL: "http://syncapod.com/logo.png", Language: "en", Category: []int{1, 2, 3}, Explicit: "clean", RSSURL: "https://syncapod.com/podcast.rss"}
	err := podStore.InsertPodcast(context.Background(), pod)
	if err != nil {
		t.Fatalf("Test_SearchPodcasts() error inserting podcast: %v", err)
	}
	pods, err := podStore.SearchPodcasts(context.Background(), "search test")
	if err != nil {
		t.Fatalf("Test_SearchPodcasts() error searching for podcasts: %v", err)
	}
	if len(pods) == 0 {
		t.Fatal("Test_SearchPodcasts() error no podcasts found")
	}
	require.Equal(t, pods[0].ID, pod.ID)
}

func Test_FindUserEpisode(t *testing.T) {
	podStore := NewPodcastStore(testDB)
	userEpi, err := podStore.FindUserEpisode(context.Background(), testUser.ID, testEpi.ID)
	if err != nil {
		t.Fatalf("Test_FindUserEpisode() error: %v", err)
	}
	require.NotEmpty(t, userEpi.ID.String())
}

func Test_UpsertUserEpisode(t *testing.T) {
	podStore := NewPodcastStore(testDB)
	upsertUserEpi := *testUserEpi
	upsertUserEpi.Offset = 654321
	err := podStore.UpsertUserEpisode(context.Background(), &upsertUserEpi)
	if err != nil {
		t.Fatalf("Test_UpsertUserEpisode() error: %v", err)
	}
	upsertUserEpi2, err := podStore.FindUserEpisode(context.Background(), upsertUserEpi.UserID, upsertUserEpi.EpisodeID)
	if err != nil {
		t.Fatalf("Test_UpsertUserEpisode() error finding user epi: %v", err)
	}
	require.Equal(t, upsertUserEpi, upsertUserEpi2)
}
