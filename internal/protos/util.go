// util.go contains conversion functions for the various db models to protobufs

package protos

import (
	"github.com/sschwartz96/syncapod-backend/internal/db"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func UserFromDB(ur *db.UserRow) *User {
	return &User{
		Id:       ur.ID.String(),
		Email:    ur.Email,
		Username: ur.Username,
		DOB:      timestamppb.New(ur.Birthdate),
	}
}
