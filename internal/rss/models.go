package rss

import "encoding/xml"

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
		Category struct {
			Text     string `xml:",chardata"`
			AttrText string `xml:"text,attr"`
			Category []struct {
				Text     string `xml:",chardata"`
				AttrText string `xml:"text,attr"`
			} `xml:"category"`
		} `xml:"category"`
		Item []rssItem `xml:"item"`
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
