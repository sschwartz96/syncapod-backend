package podcast

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sschwartz96/syncapod-backend/internal/db"
)

type Controller struct {
	podStore db.PodcastStore
	catCache *CategoryCache
}

func NewController(podStore db.PodcastStore) *Controller {
	return &Controller{podStore: podStore}
}

func (c *Controller) DoesPodcastExist(ctx context.Context, rssURL string) bool {
	// TODO: implement
	return true
}

func (c *Controller) FindPodcastsByRange(ctx context.Context, start, end int) ([]db.Podcast, error) {
	// TODO: implement
	return nil, nil
}

func (c *Controller) InsertPodcast(ctx context.Context, pod *db.Podcast) error {
	// TODO: implement
	return nil
}

func (c *Controller) UpdatePodcast(ctx context.Context, pod *db.Podcast) error {
	// TODO: implement
	return nil
}

func (c *Controller) DoesEpisodeExist(ctx context.Context, podID uuid.UUID, title string, pubDate time.Time) bool {
	// TODO: implement
	return true
}

func (c *Controller) InsertEpisode(ctx context.Context, epi *db.Episode) error {
	// TODO: implement
	return nil
}
