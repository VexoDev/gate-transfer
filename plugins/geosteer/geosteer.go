package geosteer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-logr/logr"
	"github.com/oschwald/maxminddb-golang"
	"github.com/robinbraemer/event"
	gatelite "go.minekube.com/gate/pkg/edition/java/lite"
	gateliteconfig "go.minekube.com/gate/pkg/edition/java/lite/config"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/util/configutil"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigFileName   = "config.yml"
	defaultGeoIPDatabaseKey = "GeoLite2-Country.mmdb"
)

type (
	Config struct {
		Enabled  bool   `yaml:"enabled"`
		DBPath   string `yaml:"dbPath"`
		Database string `yaml:"database"`
		Strict   bool   `yaml:"strict"`

		routeRegions map[int][]string `yaml:"-"`
	}
	fileConfig struct {
		Config struct {
			Lite struct {
				Routes []liteRouteConfig `yaml:"routes"`
			} `yaml:"lite"`
		} `yaml:"config"`
		GeoSteer *Config `yaml:"geosteer"`
	}
	liteRouteConfig struct {
		Region configutil.SingleOrMulti[string] `yaml:"region"`
	}
	LiteRouteMatch struct {
		Index       int
		RouteHost   string
		Route       *gateliteconfig.Route
		Groups      []string
		CountryCode string
		CountryName string
	}
	geoCountry struct {
		ISOCode string
		Name    string
	}
	geoCountryRecord struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"registered_country"`
	}
	runtimeState struct {
		log          logr.Logger
		db           *maxminddb.Reader
		routeRegions map[int][]string
		strict       bool
		ipCache      sync.Map
	}
)

var runtimeValue atomic.Value

func init() {
	runtimeValue.Store((*runtimeState)(nil))
}

// Plugin resolves client region data from a GeoIP database and exposes route matching for other plugins.
var Plugin = proxy.Plugin{
	Name: "GeoSteer",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx).WithName("GeoSteer")

		cfg, found, configPath, err := loadConfigSection(resolveConfigPath())
		if err != nil {
			return fmt.Errorf("loading geosteer config: %w", err)
		}
		if !found {
			log.Info("GeoSteer plugin idle: no geosteer section or route regions found")
			return nil
		}
		if !cfg.Enabled {
			setRuntime(nil)
			log.Info("GeoSteer plugin disabled by configuration")
			return nil
		}
		if len(cfg.routeRegions) == 0 {
			setRuntime(nil)
			log.Info("GeoSteer enabled but no lite route regions were configured")
			return nil
		}

		dbPath := strings.TrimSpace(cfg.DBPath)
		if dbPath == "" {
			dbPath = strings.TrimSpace(cfg.Database)
		}
		if dbPath == "" {
			dbPath = defaultGeoIPDatabaseKey
		}
		if !filepath.IsAbs(dbPath) {
			if configPath != "" {
				dbPath = filepath.Join(filepath.Dir(configPath), dbPath)
			}
		}
		dbPath = filepath.Clean(dbPath)

		db, err := maxminddb.Open(dbPath)
		if err != nil {
			return fmt.Errorf("opening geosteer GeoIP database %q: %w", dbPath, err)
		}

		state := &runtimeState{
			log:          log,
			db:           db,
			routeRegions: cfg.routeRegions,
			strict:       cfg.Strict,
		}
		setRuntime(state)

		event.Subscribe(p.Event(), 0, func(proxy.ShutdownEvent) {
			current := getRuntime()
			setRuntime(nil)
			if current != nil {
				_ = current.db.Close()
			}
		})

		log.Info("GeoSteer plugin initialized",
			"database", dbPath,
			"strict", cfg.Strict,
			"routesWithRegions", len(cfg.routeRegions),
		)
		return nil
	},
}

// MatchLiteRouteForInbound returns a region-aware route match when GeoSteer is active.
func MatchLiteRouteForInbound(in proxy.Inbound, routes []gateliteconfig.Route) (LiteRouteMatch, bool) {
	state := getRuntime()
	if state == nil {
		return LiteRouteMatch{}, false
	}
	return state.matchLiteRoute(in, routes)
}

func (s *runtimeState) matchLiteRoute(in proxy.Inbound, routes []gateliteconfig.Route) (LiteRouteMatch, bool) {
	if s == nil || len(routes) == 0 || len(s.routeRegions) == 0 {
		return LiteRouteMatch{}, false
	}

	virtualHost := "*"
	if in != nil {
		virtualHost = normalizeVirtualHost(in.VirtualHost())
		if virtualHost == "" {
			virtualHost = "*"
		}
	}

	var country geoCountry
	if in != nil {
		country = s.lookupCountry(in.RemoteAddr())
	}

	var fallbackWithoutRegion *LiteRouteMatch
	var fallbackRegionMismatch *LiteRouteMatch

	for i := range routes {
		routeHost, route, groups := gatelite.FindRouteWithGroups(virtualHost, routes[i])
		if route == nil {
			continue
		}

		candidate := LiteRouteMatch{
			Index:     i,
			RouteHost: routeHost,
			Route:     route,
			Groups:    groups,
		}
		regions := s.routeRegions[i]
		if len(regions) == 0 {
			if fallbackWithoutRegion == nil {
				copyCandidate := candidate
				fallbackWithoutRegion = &copyCandidate
			}
			continue
		}

		if country.valid() && regionsMatchCountry(regions, country) {
			candidate.CountryCode = country.ISOCode
			candidate.CountryName = country.Name
			return candidate, true
		}

		if fallbackRegionMismatch == nil {
			copyCandidate := candidate
			fallbackRegionMismatch = &copyCandidate
		}
	}

	if fallbackWithoutRegion != nil {
		return *fallbackWithoutRegion, true
	}
	if !s.strict && fallbackRegionMismatch != nil {
		return *fallbackRegionMismatch, true
	}
	return LiteRouteMatch{}, false
}

func (s *runtimeState) lookupCountry(addr net.Addr) geoCountry {
	if s == nil || s.db == nil {
		return geoCountry{}
	}

	ip := extractIP(addr)
	if ip == nil {
		return geoCountry{}
	}
	cacheKey := ip.String()
	if cached, ok := s.ipCache.Load(cacheKey); ok {
		if country, ok := cached.(geoCountry); ok {
			return country
		}
	}

	var record geoCountryRecord
	if err := s.db.Lookup(ip, &record); err != nil {
		s.log.V(1).Info("GeoSteer lookup failed", "ip", cacheKey, "error", err)
		return geoCountry{}
	}

	country := geoCountry{
		ISOCode: strings.ToUpper(strings.TrimSpace(record.Country.ISOCode)),
		Name:    strings.TrimSpace(record.Country.Names["en"]),
	}
	if country.ISOCode == "" {
		country.ISOCode = strings.ToUpper(strings.TrimSpace(record.RegisteredCountry.ISOCode))
	}
	if country.Name == "" {
		country.Name = strings.TrimSpace(record.RegisteredCountry.Names["en"])
	}

	s.ipCache.Store(cacheKey, country)
	return country
}

func (c geoCountry) valid() bool {
	return strings.TrimSpace(c.ISOCode) != "" || strings.TrimSpace(c.Name) != ""
}

func regionsMatchCountry(regions []string, country geoCountry) bool {
	if len(regions) == 0 || !country.valid() {
		return false
	}
	countryCode := normalizeRegionToken(country.ISOCode)
	countryName := normalizeRegionToken(country.Name)
	for _, region := range regions {
		if region == "" {
			continue
		}
		if region == countryCode || region == countryName {
			return true
		}
	}
	return false
}

func normalizeRegionToken(raw string) string {
	normalized := strings.TrimSpace(strings.ToLower(raw))
	if normalized == "" {
		return ""
	}

	replacer := strings.NewReplacer(
		" ", "",
		"-", "",
		"_", "",
		".", "",
		",", "",
		"'", "",
		"\"", "",
		"(", "",
		")", "",
	)
	return replacer.Replace(normalized)
}

func normalizeRegions(regions configutil.SingleOrMulti[string]) []string {
	if len(regions) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(regions))
	normalized := make([]string, 0, len(regions))
	for _, region := range regions {
		key := normalizeRegionToken(region)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, key)
	}
	return normalized
}

func extractIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}

	switch typed := addr.(type) {
	case *net.TCPAddr:
		return typed.IP
	case *net.UDPAddr:
		return typed.IP
	case *net.IPAddr:
		return typed.IP
	}

	raw := strings.TrimSpace(addr.String())
	if raw == "" {
		return nil
	}

	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	return net.ParseIP(raw)
}

func normalizeVirtualHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	cleaned := strings.TrimSpace(gatelite.ClearVirtualHost(addr.String()))
	if cleaned == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(cleaned); err == nil {
		cleaned = host
	}
	cleaned = strings.Trim(cleaned, "[]")
	cleaned = strings.Trim(cleaned, ".")
	return strings.ToLower(cleaned)
}

func getRuntime() *runtimeState {
	if loaded := runtimeValue.Load(); loaded != nil {
		if state, ok := loaded.(*runtimeState); ok {
			return state
		}
	}
	return nil
}

func setRuntime(state *runtimeState) {
	runtimeValue.Store(state)
}

func loadConfigSection(path string) (cfg Config, found bool, absPath string, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, false, "", nil
	}

	absPath, err = filepath.Abs(path)
	if err != nil {
		return Config{}, false, "", err
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, false, absPath, nil
		}
		return Config{}, false, absPath, err
	}

	var cfgFile fileConfig
	if err := yaml.Unmarshal(data, &cfgFile); err != nil {
		return Config{}, false, absPath, fmt.Errorf("parsing %s: %w", absPath, err)
	}

	cfg = Config{Enabled: true}
	if cfgFile.GeoSteer != nil {
		cfg = *cfgFile.GeoSteer
	}

	if len(cfgFile.Config.Lite.Routes) > 0 {
		cfg.routeRegions = make(map[int][]string, len(cfgFile.Config.Lite.Routes))
		for i, route := range cfgFile.Config.Lite.Routes {
			normalized := normalizeRegions(route.Region)
			if len(normalized) > 0 {
				cfg.routeRegions[i] = normalized
			}
		}
	}

	found = cfgFile.GeoSteer != nil || len(cfg.routeRegions) > 0
	return cfg, found, absPath, nil
}

func resolveConfigPath() string {
	if envPath := strings.TrimSpace(os.Getenv("GEOSTEER_CONFIG")); envPath != "" {
		return envPath
	}
	if envPath := strings.TrimSpace(os.Getenv("GATE_CONFIG")); envPath != "" {
		return envPath
	}

	args := os.Args
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--config" || arg == "-c":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(arg, "--config="):
			return strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-c="):
			return strings.TrimPrefix(arg, "-c=")
		}
	}

	return defaultConfigFileName
}
