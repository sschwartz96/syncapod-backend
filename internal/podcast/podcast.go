package podcast

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sschwartz96/syncapod-backend/internal/db"
)

type PodController struct {
	podStore *db.PodcastStore
	catCache *CategoryCache
}

func NewPodController(podStore *db.PodcastStore) (*PodController, error) {
	cats, err := podStore.FindAllCategories(context.Background())
	if err != nil {
		return nil, fmt.Errorf("NewPodController() error creating CategoryCache: %v", err)
	}
	catCache := NewCategoryCache(cats)
	return &PodController{podStore: podStore, catCache: catCache}, nil
}

func (c *PodController) DoesPodcastExist(ctx context.Context, rssURL string) bool {
	_, err := c.podStore.FindPodcastByRSS(ctx, rssURL)
	if err != nil {
		return false
	}
	return true
}

func (c *PodController) FindPodcastsByRange(ctx context.Context, start, end int) ([]db.Podcast, error) {
	// TODO: implement
	return nil, nil
}

func (c *PodController) InsertPodcast(ctx context.Context, pod *db.Podcast) error {
	return c.podStore.InsertPodcast(ctx, pod)
}

func (c *PodController) UpdatePodcast(ctx context.Context, pod *db.Podcast) error {
	// TODO: implement
	return nil
}

func (c *PodController) FindLatestEpisode(ctx context.Context, podID uuid.UUID) (*db.Episode, error) {
	return c.podStore.FindLatestEpisode(ctx, podID)
}

func (c *PodController) DoesEpisodeExist(ctx context.Context, podID uuid.UUID, title string, pubDate time.Time) bool {
	// TODO: implement
	return false
}

func (c *PodController) InsertEpisode(ctx context.Context, epi *db.Episode) error {
	return c.podStore.InsertEpisode(ctx, epi)
}
