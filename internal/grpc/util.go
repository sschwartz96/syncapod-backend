// util.go contains conversion functions for the various db models to protobufs

package grpc

import (
	"github.com/sschwartz96/syncapod-backend/internal/db"
	"github.com/sschwartz96/syncapod-backend/internal/podcast"
	"github.com/sschwartz96/syncapod-backend/internal/protos"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func userFromDB(ur *db.UserRow) *protos.User {
	return &protos.User{
		Id:       ur.ID.String(),
		Email:    ur.Email,
		Username: ur.Username,
		DOB:      timestamppb.New(ur.Birthdate),
	}
}

func podcastFromDB(pr *db.Podcast, cats []podcast.Category) *protos.Podcast {
	return &protos.Podcast{
		Id:            pr.ID.String(),
		Title:         pr.Title,
		Summary:       pr.Summary,
		Author:        pr.Author,
		Category:      podCatsToProtoCats(cats),
		Explicit:      pr.Explicit,
		Image:         &protos.Image{Url: pr.ImageURL},
		Keywords:      pr.Keywords,
		Language:      pr.Language,
		LastBuildDate: timestamppb.New(pr.PubDate), // TODO: proper build date?
		Link:          pr.LinkURL,
		PubDate:       timestamppb.New(pr.PubDate),
		Rss:           pr.RSSURL,
		Episodic:      pr.Episodic,
	}
}

func episodeFromDB(er *db.Episode) *protos.Episode {
	return &protos.Episode{
		Id:             er.ID.String(),
		PodcastID:      er.PodcastID.String(),
		Title:          er.Title,
		Subtitle:       er.Subtitle,
		EpisodeType:    er.EpisodeType,
		Image:          &protos.Image{Title: er.ImageTitle, Url: er.ImageURL},
		PubDate:        timestamppb.New(er.PubDate),
		Description:    er.Description,
		Summary:        er.Summary,
		Season:         int32(er.Season),
		Episode:        int32(er.Episode),
		Explicit:       er.Explicit,
		MP3URL:         er.EnclosureURL,
		DurationMillis: er.Duration,
	}
}

func podCatsToProtoCats(podCats []podcast.Category) []*protos.Category {
	protoCats := []*protos.Category{}
	for i, _ := range podCats {
		protoCats = append(protoCats, podCatToProtoCat(podCats[i]))
	}
	return protoCats
}

func podCatToProtoCat(podCat podcast.Category) *protos.Category {
	return &protos.Category{
		Category: podCatsToProtoCats(podCat.Subcategories),
		Text:     podCat.Name,
	}
}
