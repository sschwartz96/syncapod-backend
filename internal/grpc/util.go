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

func podcastFromDB(pr *db.Podcast, cats []*podcast.Category) *protos.Podcast {
	return &protos.Podcast{
		Id:       pr.ID.String(),
		Author:   pr.Author,
		Category: cats,
	}
}
