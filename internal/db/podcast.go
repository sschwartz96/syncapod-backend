package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

type PodcastStorePG struct {
	db *pgxpool.Pool
}

func NewPodcastStorePG(db *pgxpool.Pool) *PodcastStorePG {
	return &PodcastStorePG{db: db}
}

// scanPodcastRow is a helper method to scan row into a podcast struct
func scanPodcastRow(row pgx.Row, p *Podcast) error {
	return row.Scan(&p.ID, &p.Title, &p.Description, &p.ImageURL, &p.Language, &p.Category, &p.Explicit, &p.Author, &p.LinkURL, &p.OwnerName, &p.OwnerEmail, &p.Episodic, &p.Copyright, &p.Block, &p.Complete, &p.PubDate, &p.Keywords, &p.Summary, &p.RSSURL)
}

// scanPodcastRow is a helper method to scan row into a podcast struct
func scanEpisodeRow(row pgx.Row, e *Episode) error {
	return row.Scan(&e.ID, &e.Title, &e.EnclosureURL, &e.EnclosureLength, &e.EnclosureType, &e.PubDate, &e.Description, &e.Duration, &e.LinkURL, &e.ImageURL, &e.Explicit, &e.Episode, &e.Season, &e.EpisodeType, &e.Summary, &e.Encoded, &e.PodcastID)
}

// Podcast stuff
func (ps *PodcastStorePG) FindPodcastByRSS(ctx context.Context, rssURL string) (*Podcast, error) {
	p := &Podcast{}
	row := ps.db.QueryRow(ctx, "SELECT * FROM Podcasts WHERE rss_url=$1", rssURL)
	err := scanPodcastRow(row, p)
	if err != nil {
		return nil, fmt.Errorf("FindPodcastByRSS() error: %v", err)
	}
	return p, nil
}

func (p *PodcastStorePG) FindPodcastsByRange(ctx context.Context, start int, end int) (*[]Podcast, error) {
	panic("not implemented") // TODO: Implement
}

// Episode stuff
func (p *PodcastStorePG) FindEpisodeByTitle(ctx context.Context, podID uuid.UUID, title string) (*Episode, error) {
	panic("not implemented") // TODO: Implement
}

func (p *PodcastStorePG) FindEpisodeByURL(ctx context.Context, podID uuid.UUID, title string) (*Episode, error) {
	panic("not implemented") // TODO: Implement
}
