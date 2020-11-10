package db

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type AuthStore interface {
	// User
	InsertUser(ctx context.Context, u *UserRow) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*UserRow, error)
	GetUserByEmail(ctx context.Context, email string) (*UserRow, error)
	GetUserByUsername(ctx context.Context, username string) (*UserRow, error)
	UpdateUser(ctx context.Context, u *UserRow) error
	UpdateUserPassword(ctx context.Context, id uuid.UUID, password_hash []byte) error
	DeleteUser(ctx context.Context, id uuid.UUID) error

	// Session
	InsertSession(ctx context.Context, s *SessionRow) error
	GetSession(ctx context.Context, id uuid.UUID) (*SessionRow, error)
	UpdateSession(ctx context.Context, s *SessionRow) error
	DeleteSession(ctx context.Context, id uuid.UUID) error

	// Both
	GetSessionAndUser(ctx context.Context, sessionID uuid.UUID) (*SessionRow, *UserRow, error)
}

type OAuthStore interface {
	// Auth Code
	InsertAuthCode(ctx context.Context, a *AuthCodeRow) error
	GetAuthCode(ctx context.Context, code []byte) (*AuthCodeRow, error)
	// UpdateAuthCode(ctx context.Context, a *AuthCodeRow) error
	DeleteAuthCode(ctx context.Context, code []byte) error

	// Access Token
	InsertAccessToken(ctx context.Context, a *AccessTokenRow) error
	GetAccessTokenByRefresh(ctx context.Context, refreshToken []byte) (*AccessTokenRow, error)
	DeleteAccessToken(ctx context.Context, token []byte) error

	GetAccessTokenAndUser(ctx context.Context, token []byte) (*UserRow, *AccessTokenRow, error)
}

// UserRow contains all user specific information
type UserRow struct {
	ID           uuid.UUID
	Email        string
	Username     string
	Birthdate    time.Time
	PasswordHash []byte
}

// SessionRow contains all session information
type SessionRow struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	LoginTime    time.Time
	LastSeenTime time.Time
	Expires      time.Time
	UserAgent    string
}

// AuthCode is the authorization code of oauth2.0
// code is the primary key
type AuthCodeRow struct {
	Code     []byte    `json:"code"`
	ClientID string    `json:"client_id"`
	UserID   uuid.UUID `json:"user_id"`
	Scope    Scope     `json:"scope"`
	Expires  time.Time `json:"expires"`
}

// AccessToken contains the information to provide user access within oAuth scope
type AccessTokenRow struct {
	Token        []byte    `json:"token"`
	AuthCode     []byte    `json:"auth_code"`
	RefreshToken []byte    `json:"refresh_token"`
	UserID       uuid.UUID `json:"user_id"`
	Created      time.Time `json:"created"`
	Expires      int       `json:"expires"`
}

// Scope contains identifiers to oAuth permissions
type Scope string

// Scopes of oauth2.0
const (
	Read       Scope = "Read"
	ReadChange Scope = "ReadChange"
)

// Podcast contains information and xml struct tags for podcast
type Podcast struct {
	ID            uuid.UUID
	Title         string     `xml:"title"`
	Author        string     `xml:"author"`
	Type          string     `xml:"type"`
	Subtitle      string     `xml:"subtitle"`
	Summary       string     `xml:"summary"`
	Link          string     `xml:"Default link"`
	Image         Image      `xml:"image"`
	Explicit      string     `xml:"explicit"`
	Language      string     `xml:"language"`
	Keywords      string     `xml:"keywords"`
	Category      []Category `xml:"category"`
	PubDate       string     `xml:"pubDate"`
	LastBuildDate string     `xml:"lastBuildDate"`
	NewFeedURL    string     `xml:"new-feed-url"`
	RSS           string
	// not included in db
	Episodes []Episode `xml:"item"`
}

// Episode holds information about a single episode of a podcast within the rss feed
type Episode struct {
	ID          uuid.UUID
	PodcastID   uuid.UUID
	Title       string       `xml:"title"`
	Subtitle    string       `xml:"subtitle"`
	Author      string       `xml:"author"`
	Type        string       `xml:"type"`
	Image       EpiImage     `xml:"image"`
	Thumbnail   EpiThumbnail `xml:"content>thumbnail"`
	PubDate     string       `xml:"pubDate"`
	Description string       `xml:"description"`
	Summary     string       `xml:"summary"`
	Season      int          `xml:"season"`
	Episode     int          `xml:"episode"`
	Category    []Category   `xml:"category"`
	Explicit    string       `xml:"explicit"`
	Enclosure   Enclosure    `xml:"enclosure"`
	Duration    string       `xml:"duration"`
}

// Enclosure represents enclosure xml object that contains mp3 data
type Enclosure struct {
	MP3 string `xml:"url,attr"`
}

// Category contains the main category and secondary categories
type Category struct {
	Text     string     `xml:"text,attr"`
	Category []Category `xml:"category"`
}

// Image is the RSS image container
type Image struct {
	Title string `xml:"title"`
	URL   string `xml:"url"`
}

// EpiImage is the image container for episodes
type EpiImage struct {
	HREF string `xml:"href,attr"`
}

// EpiThumbnail is the thumbnail container for rss episodes
type EpiThumbnail struct {
	URL string `xml:"url,attr"`
}
