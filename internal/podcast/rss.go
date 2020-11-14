package podcast

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sschwartz96/syncapod-backend/internal/db"
)

type RSSController struct {
	podController *Controller
}

func NewRSSController(podController *Controller) *RSSController {
	return &RSSController{podController: podController}
}

var tzMap = map[string]string{
	"PST": "-0800", "PDT": "-0700",
	"MST": "-0700", "MDT": "-0600",
	"CST": "-0600", "CDT": "-0500",
	"EST": "-0500", "EDT": "-0400",
}

// UpdatePodcasts attempts to go through the list of podcasts update them via RSS feed
func (c *RSSController) UpdatePodcasts() error {
	var podcasts []db.Podcast
	var err error
	// just increments start and end indices
	for start, end := 0, 10; ; start, end = end, end+10 {
		podcasts, err = c.podController.FindPodcastsByRange(context.Background(), start, end)
		if err != nil || len(podcasts) == 0 {
			break // will eventually break
		}
		var wg sync.WaitGroup
		for i := range podcasts {
			pod := &podcasts[i]
			wg.Add(1)
			go func() {
				log.Println("starting updatePodcast():", pod.Title)
				err = c.updatePodcast(pod)
				if err != nil {
					fmt.Printf("UpdatePodcasts() error updating podcast %v, error = %v\n", pod, err)
				}
				log.Println("finished updatePodcast():", pod.Title)
				wg.Done()
			}()
		}
		wg.Wait()
	}
	if err != nil {
		return fmt.Errorf("UpdatePodcasts() error retrieving from db: %v", err)
	}
	return nil
}

// updatePodcast updates the given podcast via RSS feed
func (c *RSSController) updatePodcast(pod *db.Podcast) error {
	// get rss from url
	rssResp, err := downloadRSS(pod.RSSURL)
	if err != nil {
		return fmt.Errorf("updatePodcast() error downloading rss: %v", err)
	}
	// defer closing
	defer func() {
		err := rssResp.Close()
		if err != nil {
			log.Println("updatePodcast() error closing rss response:", err)
		}
	}()
	// parse rss from respone.Body
	newPod, err := parseRSS(rssResp)
	if err != nil {
		return fmt.Errorf("updatePodcast() error parsing RSS: %v", err)
	}

	for e := range newPod.Channel.Item {
		epi := c.convertEpisode(pod.ID, &newPod.Episodes[e])
		// check if the latest episode is in collection
		exists, err := c.doesEpisodeExist(epi.Title, epi.PubDate)
		if err != nil {
			fmt.Println("couldn't tell if object exists: ", err)
			continue
		}
		// episode does not exist
		if !exists {
			err = UpsertEpisode(dbClient, epi)
			if err != nil {
				fmt.Println("couldn't insert episode: ", err)
				return fmt.Errorf("updatePodcast() error upserting episode: %v", err)
			}
		} else {
			// assume that if the first podcast exists so do the rest, no need to loop through all
			break
		}
	}
	return nil
}

// AddNewPodcast takes RSS url and downloads contents inserts the podcast and its episodes into the db
// returns error if podcast already exists or connection error
func (c *RSSController) AddNewPodcast(url string) error {
	// check if podcast already contains that rss url
	_, err := (url)
	if exists {
		return errors.New("podcast already exists")
	}

	// attempt to download & parse the podcast rss
	rssResp, err := downloadRSS(url)
	if err != nil {
		return fmt.Errorf("AddNewPodcast() error downloading rss: %v", err)
	}
	// defer closing
	defer func() {
		err := rssResp.Close()
		if err != nil {
			log.Println("parseRSS() error closing r:", err)
		}
	}()

	rssPod, err := parseRSS(rssResp)
	if err != nil {
		return err
	}
	pod := convertPodcast(url, rssPod)

	// insert podcast first that way we don't add episodes without podcast
	err = dbClient.Insert(database.ColPodcast, pod)
	if err != nil {
		return fmt.Errorf("error adding new podcast: %v", err)
	}

	rssEpisodes := rssPod.RSSEpisodes

	// loop through episodes and save them
	for i := range rssEpisodes {
		rssEpi := rssEpisodes[i]
		rssEpi.ID = uuid.New()
		rssEpi.PodcastID = rssPod.ID
		if rssEpi.Author == "" {
			rssEpi.Author = pod.Author
		}

		epi := convertEpisode(pod.Id, &rssEpi)

		err = UpsertEpisode(dbClient, epi)
		if err != nil {
			fmt.Println("couldn't insert episode: ", err)
		}
	}

	return nil
}

func downloadRSS(url string) (io.ReadCloser, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// parseRSS takes in reader path and unmarshals the data
func parseRSS(r io.Reader) (*rss, error) {
	// set up rssFeed feed object and decoder
	rssFeed := &rss{}
	decoder := xml.NewDecoder(r)
	decoder.DefaultSpace = "Default"
	// decode
	err := decoder.Decode(rssFeed)
	if err != nil {
		return nil, fmt.Errorf("rss.parseRSS() error decoding rss: %v", err)
	}
	return rssFeed, nil
}

//// convertEpisode takes in id of parent podcast and RSSEpisode
//// and returns a pointer to Episode
//func convertEpisode(pID *db.ObjectID, e *models.RSSEpisode) *protos.Episode {
//	pubDate, err := parseRFC2822ToUTC(e.PubDate)
//	if err != nil {
//		fmt.Println("convertEpisode() error converting episode:", err)
//	}
//	// no error since we are checking for one above
//	pubTimestamp, _ := ptypes.TimestampProto(*pubDate)
//
//	image := &db.Image{Title: "", Url: e.Image.HREF}
//
//	dur, err := parseDuration(e.Duration)
//	if err != nil {
//		fmt.Println("convertEpisode() error parsing duration:", err)
//	}
//
//	return &db.Episode{
//		Id:             db.NewObjectID(),
//		PodcastID:      pID,
//		Title:          e.Title,
//		Description:    e.Description,
//		Subtitle:       e.Subtitle,
//		Author:         e.Author,
//		Type:           e.Type,
//		Image:          image,
//		PubDate:        pubTimestamp,
//		Summary:        e.Summary,
//		Season:         int32(e.Season),
//		Episode:        int32(e.Episode),
//		Category:       convertCategories(e.Category),
//		Explicit:       e.Explicit,
//		MP3URL:         e.Enclosure.MP3,
//		DurationMillis: dur,
//	}
//}
//
//// convertPodcast
//func convertPodcast(url string, p *models.RSSPodcast) *db.Podcast {
//
//	keywords := strings.Split(p.Keywords, ",")
//	for w := range keywords {
//		keywords[w] = strings.TrimSpace(keywords[w])
//	}
//
//	lBuildDate, err := parseRFC2822ToUTC(p.LastBuildDate)
//	if err != nil {
//		fmt.Println("convertPodcast() couldn't parse podcast build date:", err)
//	}
//	buildTimestamp, _ := ptypes.TimestampProto(*lBuildDate)
//
//	pubDate, err := parseRFC2822ToUTC(p.PubDate)
//	if err != nil {
//		fmt.Println("convertPodcast() couldn't parse podcast pubdate:", err)
//	}
//	pubTimestamp, _ := ptypes.TimestampProto(*pubDate)
//
//	return &db.Podcast{
//		Id:            db.NewObjectID(),
//		Author:        p.Author,
//		Category:      convertCategories(p.Category),
//		Explicit:      p.Explicit,
//		Image:         &db.Image{Title: p.Image.Title, Url: p.Image.URL},
//		Keywords:      keywords,
//		Language:      p.Language,
//		LastBuildDate: buildTimestamp,
//		PubDate:       pubTimestamp,
//		Link:          p.Link,
//		Rss:           url,
//		Subtitle:      p.Subtitle,
//		Title:         p.Title,
//		Type:          p.Type,
//	}
//}

func findTimezoneOffset(tz string) (string, error) {
	offset, ok := tzMap[tz]
	if !ok {
		return "", errors.New("timezone not found")
	}
	return offset, nil
}

// parseRFC2822ToUTC parses the string in RFC2822 date format
// returns pointer to time object and error
// returns time.Now() even if error occurs
func parseRFC2822ToUTC(s string) (*time.Time, error) {
	if s == "" {
		t := time.Now()
		return &t, fmt.Errorf("parseRFC2822ToUTC() no time provided")
	}
	if !strings.Contains(s, "+") && !strings.Contains(s, "-") {
		fields := strings.Fields(s)
		tz := fields[len(fields)-1]
		offset, err := findTimezoneOffset(tz)
		if err != nil {
			t := time.Now()
			return &t, err
		}
		s = strings.ReplaceAll(s, tz, offset)
	}
	t, err := time.Parse("Mon, 02 Jan 2006 15:04:05 -0700", s)
	if err != nil {
		return &t, err
	}
	return &t, nil
}

func (r *RSSController) doesEpisodeExist(podID uuid.UUID, title string, pubDate time.Time) bool {
	epi, err := r.podStore.FindEpisodeByTitle(podID, title)

}

//parseDuration takes in the string duration and returns the duration in millis
func parseDuration(d string) (int64, error) {
	if d == "" {
		return 0, fmt.Errorf("parseDuration() error empty duration string")
	}
	// check if they just applied the seconds
	if !strings.Contains(d, ":") {
		sec, err := strconv.Atoi(d)
		if err != nil {
			return 0, fmt.Errorf("parseDuration() error converting duration of episode: %v", err)
		}
		return int64(sec) * int64(1000), nil
	}
	var millis int64
	multiplier := int64(1000)

	// format hh:mm:ss || mm:ss
	split := strings.Split(d, ":")

	for i := len(split) - 1; i >= 0; i-- {
		v, _ := strconv.Atoi(split[i])
		millis += int64(v) * multiplier
		multiplier *= int64(60)
	}

	return millis, nil
}

func convertCategories(cats []models.Category) []*db.Category {
	protoCats := make([]*db.Category, len(cats))
	for i := range cats {
		protoCats[i] = convertCategory(cats[i])
	}
	return protoCats
}

func convertCategory(cat models.Category) *db.Category {
	newCat := &db.Category{
		Text:     cat.Text,
		Category: convertCategories(cat.Category),
	}
	return newCat
}

type rss struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Title       string `xml:"title"`
		Copyright   string `xml:"copyright"`
		Link        string `xml:"link"`
		Language    string `xml:"language"`
		Description string `xml:"description"`
		Author      string `xml:"author"`
		Summary     string `xml:"summary"`
		Explicit    string `xml:"explicit"`
		Image       struct {
			Text string `xml:",chardata"`
			Href string `xml:"href,attr"`
		} `xml:"image"`
		Keywords string `xml:"keywords"`
		Owner    struct {
			Text  string `xml:",chardata"`
			Name  string `xml:"name"`
			Email string `xml:"email"`
		} `xml:"owner"`
		Categories []Category `xml:"category"`
		Item       []rssItem  `xml:"item"`
	} `xml:"channel"`
}

type rssItem struct {
	Title string `xml:"title"`
	Link  string `xml:"link"`
	Guid  struct {
		Text        string `xml:",chardata"`
		IsPermaLink string `xml:"isPermaLink,attr"`
	} `xml:"guid"`
	PubDate   string `xml:"pubDate"`
	Enclosure struct {
		URL    string `xml:"url,attr"`
		Length string `xml:"length,attr"`
		Type   string `xml:"type,attr"`
	} `xml:"enclosure"`
	Description string `xml:"description"`
	Encoded     string `xml:"encoded"`
	EpisodeType string `xml:"episodeType"`
	Episode     string `xml:"episode"`
	Image       struct {
		Href string `xml:"href,attr"`
	} `xml:"image"`
	Duration string `xml:"duration"`
	Explicit string `xml:"explicit"`
	Keywords string `xml:"keywords"`
	Subtitle string `xml:"subtitle"`
	Summary  string `xml:"summary"`
	Creator  string `xml:"creator"`
	Author   string `xml:"author"`
}

type Category struct {
	ID            int
	Name          string     `xml:"text,attr"`
	Subcategories []Category `xml:"category"`
}
