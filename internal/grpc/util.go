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
		Id:       pr.ID.String(),
		Author:   pr.Author,
		Category: podCatsToProtoCats(cats),
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
