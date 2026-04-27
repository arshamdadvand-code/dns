package scanner

import (
	"fmt"
	"path/filepath"

	"masterdnsvpn-go/internal/config"
)

type FeedLoad struct {
	Endpoints []Endpoint
	Stats     FeedStats
	AbsPath   string
}

func loadFeed(path string) (FeedLoad, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return FeedLoad{}, err
	}
	resolvers, _, stats, err := config.LoadClientResolversWithStats(abs)
	if err != nil {
		return FeedLoad{}, err
	}
	out := make([]Endpoint, 0, len(resolvers))
	for _, r := range resolvers {
		if r.IP == "" || r.Port < 1 {
			continue
		}
		out = append(out, Endpoint{IP: r.IP, Port: r.Port})
	}
	return FeedLoad{
		Endpoints: out,
		Stats: FeedStats{
			TotalLines:            stats.TotalLines,
			BlankLines:            stats.BlankLines,
			CommentLines:          stats.CommentLines,
			InvalidFormatLines:    stats.InvalidFormatLines,
			DuplicateLines:        stats.DuplicateLines,
			HardInvalidScopeLines: stats.HardInvalidScopeLines,
			ExpandedFromCIDR:      stats.ExpandedFromCIDR,
			UniqueEndpoints:       stats.UniqueResolvers,
		},
		AbsPath: abs,
	}, nil
}

func (f FeedLoad) Describe() string {
	return fmt.Sprintf("feed=%s total=%d unique=%d invalid=%d dup=%d cidr_expanded=%d",
		f.AbsPath, f.Stats.TotalLines, f.Stats.UniqueEndpoints, f.Stats.InvalidFormatLines, f.Stats.DuplicateLines, f.Stats.ExpandedFromCIDR)
}
