package db

import (
	"context"
	"log"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var (
	testPod = &Podcast{ID: uuid.New(), Author: "Sam Schwartz", Description: "Syncapod Podcast", LinkURL: "https://syncapod.com/podcast", ImageURL: "http://syncapod.com/logo.png", Language: "en", Category: []int{1, 2, 3}, Explicit: "clean", RSSURL: "https://syncapod.com/podcast.rss"}
	testEpi = &Episode{ID: uuid.New(), PodcastID: testPod.ID, Title: "Test Episode", Episode: 123}
)

func setupPodcastDB() {
	podStore := NewPodcastStore(testDB)
	err := podStore.InsertPodcast(context.Background(), testPod)
	if err != nil {
		log.Fatalf("db.setupPodcastDB() error: %v", err)
	}
	err = podStore.InsertEpisode(context.Background(), testEpi)
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
