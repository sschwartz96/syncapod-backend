package grpc

import (
	"context"
	"fmt"
	"log"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/sschwartz96/syncapod-backend/internal/db"
	"github.com/sschwartz96/syncapod-backend/internal/podcast"
	"github.com/sschwartz96/syncapod-backend/internal/protos"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// PodcastService is the gRPC service for podcast
type PodcastService struct {
	*protos.UnimplementedPodServer
	podCon *podcast.PodController
}

// NewPodcastService creates a new *PodcastService
func NewPodcastService(podCon *podcast.PodController) *PodcastService {
	return &PodcastService{podCon: podCon}
}

// GetPodcast returns a podcast via id
func (p *PodcastService) GetPodcast(ctx context.Context, req *protos.Request) (*protos.Podcast, error) {
	pid, err := uuid.Parse(req.PodcastID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Could not parse podcast id: %v", err)
	}
	dbPod, err := p.podCon.FindPodcastByID(ctx, pid)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "Could not find podcast error: %v", err)
	}
	podCat, err := p.podCon.ConvertCategories(dbPod.Category)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not convert category ids: %v", err)
	}
	pod := podcastFromDB(dbPod, podCat)
	return pod, nil
}

// GetEpisodes returns a list of episodes via podcast id
func (p *PodcastService) GetEpisodes(ctx context.Context, req *protos.Request) (*protos.Episodes, error) {
	podID, err := uuid.Parse(req.PodcastID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Could not parse podcast UUID")
	}
	dbEpis, err := p.podCon.FindEpisodesByRange(ctx, podID, req.Start, req.End)
	if err != nil {
		return nil, status.Error(codes.Internal, "Could not find episodes by range")
	}
	epis := convertEpisFromDB(dbEpis)
	return &protos.Episodes{Episodes: epis}, nil
}

// GetUserEpisode returns the user playback metadata via episode id & user id
func (p *PodcastService) GetUserEpisode(ctx context.Context, req *protos.Request) (*protos.UserEpisode, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "User not authenticated")
	}
	epiID, err := uuid.Parse(req.EpisodeID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Could not parse episode uuid")
	}
	dbUserEpi, err := p.podCon.FindUserEpisode(ctx, userID, epiID)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Could not retrieve user episode: %v", err))
	}
	return convertUserEpiFromDB(dbUserEpi), nil
}

// UpdateUserEpisode updates the user playback metadata via episode id & user id
func (p *PodcastService) UpdateUserEpisode(ctx context.Context, req *protos.UserEpisodeReq) (*protos.Response, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "User not authenticated")
	}
	epiID, err := uuid.Parse(req.EpisodeID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Could not parse episode UUID")
	}
	if req.LastSeen == nil {
		req.LastSeen = ptypes.TimestampNow()
	}
	userEpi := &db.UserEpisode{
		UserID:       userID,
		EpisodeID:    epiID,
		OffsetMillis: req.Offset,
		LastSeen:     req.LastSeen.AsTime(),
		Played:       req.Played,
	}
	err = p.podCon.UpsertUserEpisode(ctx, userEpi)
	if err != nil {
		return nil, status.Error(codes.Internal, "Error upserting user epi")
	}
	return &protos.Response{Success: true, Message: ""}, nil
}

// GetSubscriptions returns a list of podcasts via user id
func (p *PodcastService) GetSubscriptions(ctx context.Context, req *protos.Request) (*protos.Subscriptions, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetSubscriptions() error getting user id: %v", err)
	}

	subs, err := p.podCon.FindSubscriptions(p.dbClient, userID)
	if err != nil {
		log.Println("GetSubscriptions() error getting subs:", err)
		return &protos.Subscriptions{}, nil
	}

	return &protos.Subscriptions{Subscriptions: subs}, nil
}

// GetUserLastPlayed returns the last episode the user was playing & metadata
func (p *PodcastService) GetUserLastPlayed(ctx context.Context, req *protos.Request) (*protos.LastPlayedRes, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetUserLastPlayed() error getting user id: %v", err)
	}

	pod, epi, userEpi, err := user.FindUserLastPlayed(p.dbClient, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUserLastPlayed() error: %v", err)
	}

	return &protos.LastPlayedRes{
		Podcast: pod,
		Episode: epi,
		Millis:  userEpi.Offset,
	}, nil
}

func getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("getUserIDFromContext() error: metadata not valid")
	}
	idString := md.Get("user_id")
	if len(idString) == 0 {
		return nil, fmt.Errorf("getUserIDFromContext() error: no user id")
	}
	return uuid.Parse(idString)
}
