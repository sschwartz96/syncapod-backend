package podcast

import (
	"context"

	"github.com/sschwartz96/syncapod-backend/internal/db"
)

type Controller struct {
	podStore db.PodcastStore
}

func NewController(podStore db.PodcastStore) *Controller {
	return &Controller{podStore: podStore}
}

func (c *Controller) DoesPodcastExist(ctx context.Context, rssURL string) bool {
	return true
}

func (c *Controller) FindPodcastsByRange(ctx context.Context, start, end int) ([]db.Podcast, error) {
	return nil, nil
}

func (c *Controller) UpdatePodcast(ctx context.Context, pod *db.Podcast) error {
	return nil
}
