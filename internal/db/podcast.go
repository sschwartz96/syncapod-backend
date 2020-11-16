package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
)

type PodcastStore struct {
	db *pgxpool.Pool
}

func NewPodcastStore(db *pgxpool.Pool) *PodcastStore {
	return &PodcastStore{db: db}
}

type scanner interface {
	Scan(...interface{}) error
}

// scanPodcastRow is a helper method to scan row into a podcast struct
func scanPodcastRow(row scanner, p *Podcast) error {
	return row.Scan(&p.ID, &p.Title, &p.Description, &p.ImageURL, &p.Language, &p.Category, &p.Explicit, &p.Author, &p.LinkURL, &p.OwnerName, &p.OwnerEmail, &p.Episodic, &p.Copyright, &p.Block, &p.Complete, &p.PubDate, &p.Keywords, &p.Summary, &p.RSSURL)
}

// scanPodcastRow is a helper method to scan row into a podcast struct
func scanEpisodeRow(row scanner, e *Episode) error {
	return row.Scan(&e.ID, &e.Title, &e.EnclosureURL, &e.EnclosureLength, &e.EnclosureType, &e.PubDate, &e.Description, &e.Duration, &e.LinkURL, &e.ImageURL, &e.Explicit, &e.Episode, &e.Season, &e.EpisodeType, &e.Summary, &e.Encoded, &e.PodcastID)
}

// Podcast stuff
func (ps *PodcastStore) InsertPodcast(ctx context.Context, p *Podcast) error {
	_, err := ps.db.Exec(ctx, "INSERT INTO Podcasts(id,title,description,image_url,language,category,explicit,author,link_url,owner_name,owner_email,episodic,copyright,block,complete,pub_date,keywords,summary,rss_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
		&p.ID, &p.Title, &p.Description, &p.ImageURL, &p.Language, &p.Category, &p.Explicit, &p.Author, &p.LinkURL, &p.OwnerName, &p.OwnerEmail, &p.Episodic, &p.Copyright, &p.Block, &p.Complete, &p.PubDate, &p.Keywords, &p.Summary, &p.RSSURL)
	if err != nil {
		return fmt.Errorf("InsertPodcast() error: %v", err)
	}
	return nil
}

func (ps *PodcastStore) FindPodcastByRSS(ctx context.Context, rssURL string) (*Podcast, error) {
	p := &Podcast{}
	row := ps.db.QueryRow(ctx, "SELECT * FROM Podcasts WHERE rss_url=$1", rssURL)
	err := scanPodcastRow(row, p)
	if err != nil {
		return nil, fmt.Errorf("FindPodcastByRSS() error: %v", err)
	}
	return p, nil
}

func (ps *PodcastStore) FindPodcastsByRange(ctx context.Context, start int, end int) ([]Podcast, error) {
	limit := end - start
	offset := start
	rows, err := ps.db.Query(ctx, "SELECT * FROM Podcast LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, fmt.Errorf("FindPodcastsByRange() error: %v", err)
	}
	p := []Podcast{}
	for rows.Next() {
		temp := &Podcast{}
		scanPodcastRow(rows, temp)
		p = append(p, *temp)
	}
	if err = rows.Err(); err != nil {
		return p, fmt.Errorf("FindPodcastsByRange() error while reading: %v", err)
	}
	return p, nil
}

// Episode stuff

func (p *PodcastStore) InsertEpisode(ctx context.Context, e *Episode) error {
	_, err := p.db.Exec(ctx, `INSERT INTO Episodes(id,title,enclosure_url,enclosure_length,enclosure_type,pub_date,description,duration,link_url,image_url,explicit,episode,season,episode_type,summary,encoded,podcast_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		&e.ID, &e.Title, &e.EnclosureURL, &e.EnclosureLength, &e.EnclosureType, &e.PubDate, &e.Description, &e.Duration, &e.LinkURL, &e.ImageURL, &e.Explicit, &e.Episode, &e.Season, &e.EpisodeType, &e.Summary, &e.Encoded, &e.PodcastID)
	if err != nil {
		return fmt.Errorf("InsertEpisode() error: %v", err)
	}
	return nil
}

func (p *PodcastStore) FindLatestEpisode(ctx context.Context, podID uuid.UUID) (*Episode, error) {
	row := p.db.QueryRow(ctx, "SELECT * FROM Episodes WHERE podcast_id=$1 ORDER BY pub_date DESC", &podID)
	epi := &Episode{}
	err := scanEpisodeRow(row, epi)
	if err != nil {
		return nil, fmt.Errorf("FindLatestEpisode() error: %v", err)
	}
	return epi, nil
}

func (p *PodcastStore) FindEpisodeByTitle(ctx context.Context, podID uuid.UUID, title string) (*Episode, error) {
	panic("not implemented") // TODO: Implement
}

func (p *PodcastStore) FindEpisodeByURL(ctx context.Context, podID uuid.UUID, title string) (*Episode, error) {
	panic("not implemented") // TODO: Implement
}

func (p *PodcastStore) FindAllCategories(ctx context.Context) ([]Category, error) {
	cats := []Category{}
	rows, err := p.db.Query(ctx, "SELECT * FROM Categories")
	if err != nil {
		return cats, fmt.Errorf("FindAllCategories() error: %v", err)
	}
	for rows.Next() {
		temp := Category{}
		rows.Scan(&temp.ID, &temp.Name, &temp.ParentID)
		cats = append(cats, temp)
	}
	if err = rows.Err(); err != nil {
		return cats, fmt.Errorf("FindAllCategories() error reading rows: %v", err)
	}
	return cats, nil
}
