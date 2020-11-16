package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func Test_InsertPodcast(t *testing.T) {
	podStore := NewPodcastStore(testDB)
	pod := &Podcast{ID: uuid.New(), Author: "Sam Schwartz", Description: "Syncapod Podcast", LinkURL: "https://syncapod.com/podcast", ImageURL: "http://syncapod.com/logo.png", Language: "en", Category: []int{1, 2, 3}, Explicit: "clean", RSSURL: "https://syncapod.com/podcast.rss"}
	err := podStore.InsertPodcast(context.Background(), pod)
	if err != nil {
		t.Fatalf("Test_InsertPodcast() error: %v", err)
	}
}
