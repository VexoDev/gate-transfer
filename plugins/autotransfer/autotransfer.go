package autotransfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Tnze/go-mc/bot"
	"github.com/Tnze/go-mc/data/packetid"
	mcnet "github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/go-logr/logr"
	"github.com/pires/go-proxyproto"
	"github.com/robinbraemer/event"
	"go.minekube.com/gate/pkg/edition/java/forge/modinfo"
	gatelite "go.minekube.com/gate/pkg/edition/java/lite"
	gateliteconfig "go.minekube.com/gate/pkg/edition/java/lite/config"
	javaping "go.minekube.com/gate/pkg/edition/java/ping"
	"go.minekube.com/gate/pkg/edition/java/proto/version"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	gateproto "go.minekube.com/gate/pkg/gate/proto"
	"go.minekube.com/gate/pkg/util/configutil"
	"go.minekube.com/gate/pkg/util/netutil"
	"go.minekube.com/gate/pkg/util/validation"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigFileName = "config.yml"
	legacyConfigFileName  = "autotransfer.yml"
	defaultTargetServer   = "autotransfer"
	defaultTransferPort   = "25565"
)

var (
	// ErrNoAddressConfigured is returned when a target backend address cannot be resolved.
	ErrNoAddressConfigured = errors.New("no target address configured")
)

// Plugin automatically transfers newly joined players to a configured host.
var Plugin = proxy.Plugin{
	Name: "AutoTransfer",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)

		setTargetAddress("")

		cfg, err := LoadConfig(log)
		if err != nil {
			return fmt.Errorf("loading autotransfer config: %w", err)
		}

		if !cfg.Enabled {
			log.Info("AutoTransfer plugin disabled by configuration")
			return nil
		}
		if p.Config().Lite.Enabled {
			log.Info("config.lite.enabled is true; Gate lite mode handles login forwarding directly, so autotransfer transfer packets are bypassed")
		}

		resolver, err := NewTargetResolver(log.WithName("targetResolver"), p, cfg)
		if err != nil {
			return err
		}
		if !resolver.HasPotentialTarget() {
			return errors.New("autotransfer enabled but no target available; configure autotransfer.targetHost/targetServer, config.try, or config.lite.routes")
		}

		defaultServer, defaultAddr, err := resolver.ResolveForVirtualHost("")
		if err != nil {
			log.V(1).Info("no default auto-transfer target could be resolved at startup", "error", err)
		}
		statusResolver := NewStatusResolver(log.WithName("backendStatus"), 2*time.Second, 10*time.Second)

		pl := &plugin{
			log:           log,
			cfg:           cfg,
			resolver:      resolver,
			status:        statusResolver,
			defaultServer: defaultServer,
			defaultAddr:   defaultAddr,
		}
		event.Subscribe(p.Event(), 0, pl.onChooseInitialServer)
		event.Subscribe(p.Event(), 0, pl.onServerPreConnect)
		event.Subscribe(p.Event(), 0, pl.onServerPostConnect)
		event.Subscribe(p.Event(), 0, pl.onDisconnect)
		event.Subscribe(p.Event(), 0, pl.onPing)

		targetName := ""
		if defaultServer != nil {
			targetName = defaultServer.ServerInfo().Name()
		}

		log.Info("AutoTransfer plugin initialized",
			"targetServer", targetName,
			"targetAddr", defaultAddr,
			"delay", cfg.Delay,
		)
		return nil
	},
}

type plugin struct {
	log           logr.Logger
	cfg           Config
	resolver      *TargetResolver
	status        *StatusResolver
	defaultServer proxy.RegisteredServer
	defaultAddr   string
	transferSent  sync.Map
	skipInitial   sync.Map
}

type Config struct {
	Enabled      bool          `yaml:"enabled"`
	TargetHost   string        `yaml:"targetHost"`
	TargetServer string        `yaml:"targetServer"`
	Transfer     bool          `yaml:"transfer"`
	Delay        time.Duration `yaml:"delay"`

	liteRouteTransfer        map[int]bool                                `yaml:"-"`
	liteRouteBackendTransfer map[int]configutil.SingleOrMulti[string]    `yaml:"-"`
	liteRouteTransferHostMap map[string]bool                             `yaml:"-"`
	liteRouteBackendHostMap  map[string]configutil.SingleOrMulti[string] `yaml:"-"`
}

type fileConfig struct {
	Config struct {
		Lite struct {
			Routes []liteRouteConfig `yaml:"routes"`
		} `yaml:"lite"`
	} `yaml:"config"`
	AutoTransfer *Config `yaml:"autotransfer"`
}

type liteRouteConfig struct {
	Host            configutil.SingleOrMulti[string] `yaml:"host"`
	Transfer        *bool                            `yaml:"transfer"`
	BackendTransfer configutil.SingleOrMulti[string] `yaml:"backend-transfer"`
}

type ResolvedTarget struct {
	Server               proxy.RegisteredServer
	Address              string
	UseTransfer          bool
	BackendProxyProtocol bool
}

func (c Config) transferForLiteRoute(index int, routeHost string) bool {
	if c.liteRouteTransferHostMap != nil {
		if routeTransfer, ok := c.liteRouteTransferHostMap[normalizeRouteHostKey(routeHost)]; ok {
			return routeTransfer
		}
	}
	if c.liteRouteTransfer != nil {
		if routeTransfer, ok := c.liteRouteTransfer[index]; ok {
			return routeTransfer
		}
	}
	return c.Transfer
}

func (c Config) backendTransferForLiteRoute(index int, routeHost string) configutil.SingleOrMulti[string] {
	if c.liteRouteBackendHostMap != nil {
		if routeBackendTransfer, ok := c.liteRouteBackendHostMap[normalizeRouteHostKey(routeHost)]; ok {
			return routeBackendTransfer
		}
	}
	if c.liteRouteBackendTransfer != nil {
		if routeBackendTransfer, ok := c.liteRouteBackendTransfer[index]; ok {
			return routeBackendTransfer
		}
	}
	return nil
}

// TargetResolver resolves transfer destinations from autotransfer settings,
// standard Gate server config, and lite mode routes.
type TargetResolver struct {
	log   logr.Logger
	proxy *proxy.Proxy
	cfg   Config

	strategyManager *gatelite.StrategyManager
	targetServer    string

	explicitServerConfigured bool
	explicitTargetAddr       net.Addr
	explicitTargetAddress    string

	mu           sync.Mutex
	serversByKey map[string]proxy.RegisteredServer
}

// NewTargetResolver creates a target resolver that can resolve host-specific backends.
func NewTargetResolver(log logr.Logger, p *proxy.Proxy, cfg Config) (*TargetResolver, error) {
	if p == nil {
		return nil, errors.New("proxy instance is nil")
	}

	targetServer := strings.TrimSpace(cfg.TargetServer)
	explicitServerConfigured := targetServer != ""
	if targetServer == "" {
		targetServer = defaultTargetServer
	}
	if !validation.ValidServerName(targetServer) {
		return nil, fmt.Errorf("invalid targetServer %q: %s", targetServer, validation.QualifiedNameErrMsg)
	}

	r := &TargetResolver{
		log:                      log,
		proxy:                    p,
		cfg:                      cfg,
		targetServer:             targetServer,
		explicitServerConfigured: explicitServerConfigured,
		serversByKey:             make(map[string]proxy.RegisteredServer),
	}

	if liteProxy := p.Lite(); liteProxy != nil {
		r.strategyManager = liteProxy.StrategyManager()
	}

	if host := strings.TrimSpace(cfg.TargetHost); host != "" {
		parsedAddr, addrString, err := parseTargetAddr(host)
		if err != nil {
			return nil, fmt.Errorf("invalid targetHost %q: %w", host, err)
		}
		r.explicitTargetAddr = parsedAddr
		r.explicitTargetAddress = addrString
	}

	return r, nil
}

// HasPotentialTarget returns whether this resolver has at least one target source.
func (r *TargetResolver) HasPotentialTarget() bool {
	if r.explicitTargetAddress != "" || r.explicitServerConfigured {
		return true
	}
	cfg := r.proxy.Config()
	if len(cfg.Lite.Routes) > 0 {
		return true
	}
	if len(cfg.Try) > 0 {
		return true
	}
	if r.proxy.Server(r.targetServer) != nil {
		return true
	}
	return len(r.proxy.Servers()) > 0
}

// ResolveForInbound resolves the target server and address for a specific inbound connection.
func (r *TargetResolver) ResolveForInbound(in proxy.Inbound) (proxy.RegisteredServer, string, error) {
	target, err := r.ResolveTargetForInbound(in)
	if err != nil {
		return nil, "", err
	}
	return target.Server, target.Address, nil
}

// ResolveTargetForInbound resolves target details for a specific inbound connection.
func (r *TargetResolver) ResolveTargetForInbound(in proxy.Inbound) (ResolvedTarget, error) {
	if in == nil {
		return r.resolveTargetForVirtualHost("", gateproto.Protocol(0))
	}
	return r.resolveTargetForVirtualHost(normalizeVirtualHost(in.VirtualHost()), in.Protocol())
}

// ResolveForVirtualHost resolves the target for a specific virtual host.
func (r *TargetResolver) ResolveForVirtualHost(virtualHost string) (proxy.RegisteredServer, string, error) {
	target, err := r.ResolveTargetForVirtualHost(virtualHost)
	if err != nil {
		return nil, "", err
	}
	return target.Server, target.Address, nil
}

// ResolveTargetForVirtualHost resolves target details for a specific virtual host.
func (r *TargetResolver) ResolveTargetForVirtualHost(virtualHost string) (ResolvedTarget, error) {
	return r.resolveTargetForVirtualHost(virtualHost, gateproto.Protocol(0))
}

func (r *TargetResolver) resolveTargetForVirtualHost(virtualHost string, protocolVersion gateproto.Protocol) (ResolvedTarget, error) {
	canUseTransfer := protocolVersion.GreaterEqual(version.Minecraft_1_20_5)

	if r.explicitTargetAddress != "" {
		server, err := r.serverForAddress(r.explicitTargetAddress, r.explicitTargetAddr, r.targetServer, false)
		if err != nil {
			return ResolvedTarget{}, err
		}
		setTargetAddress(r.explicitTargetAddress)
		return ResolvedTarget{
			Server:      server,
			Address:     r.explicitTargetAddress,
			UseTransfer: canUseTransfer && r.cfg.Transfer,
		}, nil
	}

	if r.explicitServerConfigured {
		server := r.proxy.Server(r.targetServer)
		if server == nil {
			return ResolvedTarget{}, fmt.Errorf("configured targetServer %q is not registered", r.targetServer)
		}
		addr, err := serverAddrString(server)
		if err != nil {
			return ResolvedTarget{}, err
		}
		setTargetAddress(addr)
		return ResolvedTarget{
			Server:      server,
			Address:     addr,
			UseTransfer: canUseTransfer && r.cfg.Transfer,
		}, nil
	}

	if len(r.proxy.Config().Lite.Routes) > 0 {
		target, err := r.resolveFromLite(virtualHost, canUseTransfer)
		if err == nil {
			setTargetAddress(target.Address)
			return target, nil
		}
		r.log.V(1).Info("unable to resolve target from lite route", "virtualHost", virtualHost, "error", err)
	}

	target, err := r.resolveFromDefaults()
	if err == nil {
		setTargetAddress(target.Address)
		return target, nil
	}

	return ResolvedTarget{}, ErrNoAddressConfigured
}

func (r *TargetResolver) resolveFromLite(virtualHost string, canUseTransfer bool) (ResolvedTarget, error) {
	routes := r.proxy.Config().Lite.Routes
	if len(routes) == 0 {
		return ResolvedTarget{}, errors.New("lite mode has no routes")
	}

	host := normalizeVirtualHostString(virtualHost)
	if host == "" {
		host = "*"
	}

	routeHost, route, groups := gatelite.FindRouteWithGroups(host, routes...)
	if route == nil {
		return ResolvedTarget{}, fmt.Errorf("no lite route matched virtual host %q", host)
	}
	if len(route.Backend) == 0 {
		return ResolvedTarget{}, fmt.Errorf("matched lite route %q has no backend", routeHost)
	}
	routeIndex := findLiteRouteIndexByHost(routes, routeHost)
	if routeIndex < 0 {
		routeIndex = findLiteRouteIndex(routes, route)
	}

	backends := route.Backend.Copy()
	backendAddr := backends[0]
	if r.strategyManager != nil {
		selected, _, ok := r.strategyManager.GetNextBackend(r.log.WithName("liteStrategy"), route, routeHost, backends)
		if ok {
			backendAddr = selected
		}
	}

	backendAddr = substituteBackendParams(backendAddr, groups)
	parsedAddr, addrString, err := parseTargetAddr(backendAddr)
	if err != nil {
		return ResolvedTarget{}, fmt.Errorf("invalid lite backend %q: %w", backendAddr, err)
	}
	transferAddr := addrString
	backendProxyProtocol := route.ProxyProtocol
	useTransfer := canUseTransfer && r.cfg.transferForLiteRoute(routeIndex, routeHost)
	if canUseTransfer {
		if backendTransfer := r.cfg.backendTransferForLiteRoute(routeIndex, routeHost); len(backendTransfer) > 0 {
			selectedTransferAddr := backendTransfer[0]
			if r.strategyManager != nil {
				transferCandidates := backendTransfer.Copy()
				if selected, _, ok := r.strategyManager.GetNextBackend(r.log.WithName("liteTransferStrategy"), route, routeHost, transferCandidates); ok {
					selectedTransferAddr = selected
				}
			}
			selectedTransferAddr = substituteBackendParams(selectedTransferAddr, groups)
			_, transferAddress, transferErr := parseTargetAddr(selectedTransferAddr)
			if transferErr != nil {
				return ResolvedTarget{}, fmt.Errorf("invalid lite backend-transfer %q: %w", selectedTransferAddr, transferErr)
			}
			transferAddr = transferAddress
			// Transfer backends are usually direct/public endpoints and should not
			// receive HAProxy headers unless explicitly handled by that endpoint.
			backendProxyProtocol = false
			useTransfer = true
		}
	}

	serverName := generatedServerName(r.targetServer, addrString)
	server, err := r.serverForAddress(addrString, parsedAddr, serverName, route.ProxyProtocol)
	if err != nil {
		return ResolvedTarget{}, err
	}

	return ResolvedTarget{
		Server:               server,
		Address:              transferAddr,
		UseTransfer:          useTransfer,
		BackendProxyProtocol: backendProxyProtocol,
	}, nil
}

func (r *TargetResolver) resolveFromDefaults() (ResolvedTarget, error) {
	for _, name := range r.proxy.Config().Try {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		server := r.proxy.Server(name)
		if server == nil {
			continue
		}
		addr, err := serverAddrString(server)
		if err != nil {
			continue
		}
		return ResolvedTarget{
			Server:      server,
			Address:     addr,
			UseTransfer: r.cfg.Transfer,
		}, nil
	}

	if server := r.proxy.Server(r.targetServer); server != nil {
		addr, err := serverAddrString(server)
		if err == nil {
			return ResolvedTarget{
				Server:      server,
				Address:     addr,
				UseTransfer: r.cfg.Transfer,
			}, nil
		}
	}

	servers := r.proxy.Servers()
	if len(servers) == 1 {
		addr, err := serverAddrString(servers[0])
		if err == nil {
			return ResolvedTarget{
				Server:      servers[0],
				Address:     addr,
				UseTransfer: r.cfg.Transfer,
			}, nil
		}
	}

	return ResolvedTarget{}, errors.New("no default backend server found")
}

func (r *TargetResolver) serverForAddress(addrString string, parsedAddr net.Addr, preferredName string, proxyProtocol bool) (proxy.RegisteredServer, error) {
	addrString = strings.TrimSpace(addrString)
	if addrString == "" {
		return nil, errors.New("empty target address")
	}
	if parsedAddr == nil {
		return nil, errors.New("nil target address")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := serverTargetKey(addrString, proxyProtocol)
	if server := r.serversByKey[key]; server != nil {
		return server, nil
	}

	if existing := r.findServerByAddress(addrString, proxyProtocol); existing != nil {
		r.serversByKey[key] = existing
		return existing, nil
	}

	name := strings.TrimSpace(preferredName)
	if name == "" {
		name = generatedServerName(r.targetServer, addrString)
	}
	if !validation.ValidServerName(name) {
		name = generatedServerName(defaultTargetServer, addrString)
	}

	if existing := r.proxy.Server(name); existing != nil {
		existingAddr, err := serverAddrString(existing)
		if err == nil && sameAddress(existingAddr, addrString) && serverUsesProxyProtocol(existing) == proxyProtocol {
			r.serversByKey[key] = existing
			return existing, nil
		}
		name = generatedServerName(name, serverTargetKey(addrString, proxyProtocol))
	}

	serverInfo := newAutoTransferServerInfo(name, parsedAddr, proxyProtocol)
	server, err := r.proxy.Register(serverInfo)
	if err != nil {
		if errors.Is(err, proxy.ErrServerAlreadyExists) {
			existing := r.proxy.Server(name)
			if existing != nil {
				existingAddr, addrErr := serverAddrString(existing)
				if addrErr == nil && sameAddress(existingAddr, addrString) && serverUsesProxyProtocol(existing) == proxyProtocol {
					r.serversByKey[key] = existing
					return existing, nil
				}
			}
		}
		return nil, fmt.Errorf("registering target server %q: %w", name, err)
	}

	r.log.V(1).Info("registered auto-transfer server", "name", serverInfo.Name(), "addr", addrString, "proxyProtocol", proxyProtocol)
	r.serversByKey[key] = server
	return server, nil
}

func (r *TargetResolver) findServerByAddress(addr string, proxyProtocol bool) proxy.RegisteredServer {
	for _, server := range r.proxy.Servers() {
		serverAddr, err := serverAddrString(server)
		if err != nil {
			continue
		}
		if sameAddress(serverAddr, addr) && serverUsesProxyProtocol(server) == proxyProtocol {
			return server
		}
	}
	return nil
}

var targetAddr atomic.Value

func init() {
	targetAddr.Store("")
}

// TargetAddress returns the destination address currently resolved by the AutoTransfer plugin.
func TargetAddress() string {
	if v := targetAddr.Load(); v != nil {
		if addr, ok := v.(string); ok {
			return addr
		}
	}
	return ""
}

func setTargetAddress(addr string) {
	targetAddr.Store(strings.TrimSpace(addr))
}

// LoadConfig reads AutoTransfer configuration from config.yml, with fallback to legacy autotransfer.yml.
func LoadConfig(log logr.Logger) (Config, error) {
	configPath := resolveConfigPath()

	cfg, found, absPath, err := loadConfigSection(configPath)
	if err != nil {
		return Config{}, err
	}
	if found {
		return cfg, nil
	}

	legacyCfg, legacyFound, legacyPath, legacyErr := loadConfigSection(legacyConfigFileName)
	if legacyErr != nil {
		return Config{}, legacyErr
	}
	if legacyFound {
		log.Info("Loaded legacy autotransfer.yml config; migrate this block to config.yml under autotransfer", "path", legacyPath)
		return legacyCfg, nil
	}

	if absPath != "" {
		log.Info("AutoTransfer config section not found; using defaults", "path", absPath)
	}
	return Config{}, nil
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
	if cfgFile.AutoTransfer == nil {
		return Config{}, false, absPath, nil
	}

	cfg = *cfgFile.AutoTransfer
	if len(cfgFile.Config.Lite.Routes) > 0 {
		cfg.liteRouteTransfer = make(map[int]bool, len(cfgFile.Config.Lite.Routes))
		cfg.liteRouteBackendTransfer = make(map[int]configutil.SingleOrMulti[string], len(cfgFile.Config.Lite.Routes))
		cfg.liteRouteTransferHostMap = make(map[string]bool, len(cfgFile.Config.Lite.Routes))
		cfg.liteRouteBackendHostMap = make(map[string]configutil.SingleOrMulti[string], len(cfgFile.Config.Lite.Routes))
		for i, route := range cfgFile.Config.Lite.Routes {
			if route.Transfer == nil {
				// keep default transfer behavior
			} else {
				cfg.liteRouteTransfer[i] = *route.Transfer
				for _, host := range route.Host {
					key := normalizeRouteHostKey(host)
					if key != "" {
						cfg.liteRouteTransferHostMap[key] = *route.Transfer
					}
				}
			}
			if len(route.BackendTransfer) > 0 {
				cfg.liteRouteBackendTransfer[i] = route.BackendTransfer
				for _, host := range route.Host {
					key := normalizeRouteHostKey(host)
					if key != "" {
						cfg.liteRouteBackendHostMap[key] = route.BackendTransfer
					}
				}
			}
		}
	}

	return cfg, true, absPath, nil
}

func resolveConfigPath() string {
	if envPath := strings.TrimSpace(os.Getenv("AUTOTRANSFER_CONFIG")); envPath != "" {
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

func (p *plugin) onServerPostConnect(e *proxy.ServerPostConnectEvent) {
	if !p.cfg.Enabled || p.resolver == nil {
		return
	}
	// Only run for the first backend connection after login.
	if e.PreviousServer() != nil {
		return
	}
	player := e.Player()
	if p.cfg.Delay <= 0 {
		p.transferPlayer(player)
		return
	}
	go func() {
		select {
		case <-time.After(p.cfg.Delay):
		case <-player.Context().Done():
			return
		}
		p.transferPlayer(player)
	}()
}

func (p *plugin) onDisconnect(e *proxy.DisconnectEvent) {
	key := transferAttemptKey(e.Player())
	p.transferSent.Delete(key)
	p.skipInitial.Delete(key)
}

func (p *plugin) onServerPreConnect(e *proxy.ServerPreConnectEvent) {
	if !p.cfg.Enabled || p.resolver == nil {
		return
	}
	// Keep delayed transfers on post-connect path only.
	if p.cfg.Delay > 0 {
		return
	}
	// Only intercept the initial backend connect during login.
	if e.PreviousServer() != nil {
		return
	}

	player := e.Player()
	if p.consumeSkipInitialConnect(player) {
		e.Deny()
		if player.Context().Err() == nil {
			p.log.Info("autotransfer preconnect: denied initial backend connect after transfer",
				"player", player.Username(),
				"protocol", player.Protocol(),
			)
		}
		return
	}

	target, err := p.resolver.ResolveTargetForInbound(player)
	if err != nil {
		if !errors.Is(err, ErrNoAddressConfigured) {
			p.log.V(1).Info("autotransfer preconnect target resolve failed", "player", player.Username(), "protocol", player.Protocol(), "error", err)
		}
		return
	}
	if target.Server == nil || target.Address == "" {
		p.log.Info("autotransfer preconnect skipped: missing target",
			"player", player.Username(),
			"protocol", player.Protocol(),
			"targetServerNil", target.Server == nil,
			"targetAddr", target.Address,
		)
		return
	}
	if !target.UseTransfer {
		p.log.Info("autotransfer preconnect skipped: transfer disabled",
			"player", player.Username(),
			"protocol", player.Protocol(),
			"targetServer", target.Server.ServerInfo().Name(),
			"targetAddr", target.Address,
		)
		return
	}
	if !player.Protocol().GreaterEqual(version.Minecraft_1_20_5) {
		p.log.Info("autotransfer preconnect skipped: client protocol < 1.20.5",
			"player", player.Username(),
			"protocol", player.Protocol(),
			"targetServer", target.Server.ServerInfo().Name(),
			"targetAddr", target.Address,
		)
		return
	}
	if e.Server() == nil {
		p.log.Info("autotransfer preconnect skipped: event server is nil",
			"player", player.Username(),
			"protocol", player.Protocol(),
			"targetServer", target.Server.ServerInfo().Name(),
			"targetAddr", target.Address,
		)
		return
	}

	if !p.beginTransferAttempt(player) {
		// Transfer was already attempted/sent for this login. Prevent redundant backend dial.
		e.Deny()
		return
	}
	p.log.Info("autotransfer preconnect: attempting transfer",
		"player", player.Username(),
		"protocol", player.Protocol(),
		"targetServer", target.Server.ServerInfo().Name(),
		"targetAddr", target.Address,
		"eventServer", e.Server().ServerInfo().Name(),
	)
	if err := player.TransferToHost(target.Address); err != nil {
		p.transferSent.Delete(transferAttemptKey(player))
		if !errors.Is(err, proxy.ErrTransferUnsupportedClientProtocol) && player.Context().Err() == nil {
			p.log.Error(err, "auto transfer before initial backend connect failed", "player", player.Username(), "address", target.Address)
		} else if player.Context().Err() == nil {
			p.log.Info("auto transfer before initial backend connect unsupported; falling back to normal connect",
				"player", player.Username(), "protocol", player.Protocol(), "address", target.Address)
		}
		return // allow the normal initial backend connect as fallback
	}

	e.Deny()
	if player.Context().Err() == nil {
		p.log.Info("sent transfer packet before initial backend connect", "player", player.Username(), "address", target.Address)
	}
}

func (p *plugin) onPing(e *proxy.PingEvent) {
	if p.resolver == nil || p.status == nil {
		return
	}

	target, err := p.resolver.ResolveTargetForInbound(e.Connection())
	if err != nil && !errors.Is(err, ErrNoAddressConfigured) {
		p.log.V(1).Info("failed to resolve ping backend target", "error", err)
	}

	addr := target.Address
	if addr == "" && target.Server != nil {
		if serverAddr, serverErr := serverAddrString(target.Server); serverErr == nil {
			addr = serverAddr
		}
	}

	query := StatusQuery{
		Addr:          addr,
		ProxyProtocol: target.BackendProxyProtocol,
	}
	if conn := e.Connection(); conn != nil {
		query.SourceAddr = conn.RemoteAddr()
		query.VirtualHost = normalizeVirtualHost(conn.VirtualHost())
	}

	status, err := p.status.Status(context.Background(), query)
	if err != nil {
		if !errors.Is(err, ErrNoAddressConfigured) {
			p.log.V(1).Info("failed to update backend status", "address", addr, "virtualHost", query.VirtualHost, "proxyProtocol", query.ProxyProtocol, "error", err)
		}
		return
	}
	if status == nil {
		return
	}

	base := e.Ping()
	if status.Players == nil {
		status.Players = &javaping.Players{}
	}
	status.Version = base.Version
	e.SetPing(status)
}

func (p *plugin) onChooseInitialServer(e *proxy.PlayerChooseInitialServerEvent) {
	if !p.cfg.Enabled || p.resolver == nil {
		return
	}

	player := e.Player()
	target, err := p.resolver.ResolveTargetForInbound(e.Player())
	if err != nil || target.Server == nil {
		if err != nil && !errors.Is(err, ErrNoAddressConfigured) {
			p.log.V(1).Info("unable to resolve initial server target", "player", e.Player().Username(), "error", err)
		}
		if p.defaultServer == nil {
			return
		}
		target.Server = p.defaultServer
	}

	if p.cfg.Delay <= 0 &&
		target.Server != nil &&
		target.Address != "" &&
		target.UseTransfer &&
		player.Protocol().GreaterEqual(version.Minecraft_1_20_5) {
		key := transferAttemptKey(player)
		if p.beginTransferAttempt(player) {
			p.log.Info("autotransfer choose-initial: attempting transfer",
				"player", player.Username(),
				"protocol", player.Protocol(),
				"targetServer", target.Server.ServerInfo().Name(),
				"targetAddr", target.Address,
			)
			if transferErr := player.TransferToHost(target.Address); transferErr == nil {
				p.skipInitial.Store(key, struct{}{})
				p.log.Info("sent transfer packet during initial server selection",
					"player", player.Username(),
					"protocol", player.Protocol(),
					"address", target.Address,
				)
			} else {
				p.transferSent.Delete(key)
				if !errors.Is(transferErr, proxy.ErrTransferUnsupportedClientProtocol) {
					p.log.Error(transferErr, "auto transfer in initial server selection failed", "player", player.Username(), "address", target.Address)
				} else {
					p.log.Info("auto transfer in initial server selection unsupported; using normal backend connect",
						"player", player.Username(), "protocol", player.Protocol(), "address", target.Address)
				}
			}
		}
	}

	if current := e.InitialServer(); current != nil && proxy.RegisteredServerEqual(current, target.Server) {
		return
	}

	p.log.Info("autotransfer choose initial server",
		"player", e.Player().Username(),
		"protocol", e.Player().Protocol(),
		"selectedServer", target.Server.ServerInfo().Name(),
		"selectedAddr", target.Address,
		"useTransfer", target.UseTransfer,
	)
	e.SetInitialServer(target.Server)
}

func (p *plugin) transferPlayer(player proxy.Player) {
	target, err := p.resolver.ResolveTargetForInbound(player)
	if err != nil {
		if !errors.Is(err, ErrNoAddressConfigured) {
			p.log.V(1).Info("unable to resolve transfer target", "player", player.Username(), "error", err)
		}
		return
	}
	if target.Address == "" || !target.UseTransfer {
		return
	}

	key := transferAttemptKey(player)
	if !p.beginTransferAttempt(player) {
		return
	}

	if err := player.TransferToHost(target.Address); err != nil {
		p.transferSent.Delete(key)
		if errors.Is(err, proxy.ErrTransferUnsupportedClientProtocol) {
			p.connectFallback(player, target.Server)
			return
		}
		if player.Context().Err() == nil {
			p.log.Error(err, "auto transfer failed", "player", player.Username(), "address", target.Address)
		}
		p.connectFallback(player, target.Server)
		return
	}
	if player.Context().Err() == nil {
		p.log.Info("sent transfer packet", "player", player.Username(), "address", target.Address)
	}
}

func (p *plugin) beginTransferAttempt(player proxy.Player) bool {
	_, loaded := p.transferSent.LoadOrStore(transferAttemptKey(player), struct{}{})
	return !loaded
}

func transferAttemptKey(player proxy.Player) string {
	return player.ID().String()
}

func (p *plugin) consumeSkipInitialConnect(player proxy.Player) bool {
	key := transferAttemptKey(player)
	if _, ok := p.skipInitial.Load(key); !ok {
		return false
	}
	p.skipInitial.Delete(key)
	return true
}

func (p *plugin) connectFallback(player proxy.Player, target proxy.RegisteredServer) {
	if target == nil {
		return
	}
	if current := player.CurrentServer(); current != nil && proxy.RegisteredServerEqual(current.Server(), target) {
		return
	}
	if success := player.CreateConnectionRequest(target).ConnectWithIndication(player.Context()); !success && player.Context().Err() == nil {
		p.log.Info("auto transfer fallback failed", "player", player.Username(), "targetServer", target.ServerInfo().Name())
	}
}

func parseTargetAddr(raw string) (net.Addr, string, error) {
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" {
		return nil, "", errors.New("empty address")
	}

	if _, _, err := net.SplitHostPort(cleaned); err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" {
			cleaned = net.JoinHostPort(cleaned, defaultTransferPort)
		} else {
			return nil, "", err
		}
	}

	addr, err := netutil.Parse(cleaned, "tcp")
	if err != nil {
		return nil, "", err
	}

	return addr, addr.String(), nil
}

func serverAddrString(server proxy.RegisteredServer) (string, error) {
	if server == nil {
		return "", errors.New("nil server")
	}
	infoAddr := server.ServerInfo().Addr()
	if infoAddr == nil {
		return "", fmt.Errorf("server %q has no address", server.ServerInfo().Name())
	}

	_, addr, err := parseTargetAddr(infoAddr.String())
	if err != nil {
		return strings.TrimSpace(infoAddr.String()), nil
	}
	return addr, nil
}

func normalizeVirtualHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return normalizeVirtualHostString(addr.String())
}

func normalizeVirtualHostString(raw string) string {
	cleaned := strings.TrimSpace(gatelite.ClearVirtualHost(raw))
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

func sameAddress(a, b string) bool {
	_, normalizedA, errA := parseTargetAddr(a)
	if errA != nil {
		normalizedA = strings.TrimSpace(a)
	}
	_, normalizedB, errB := parseTargetAddr(b)
	if errB != nil {
		normalizedB = strings.TrimSpace(b)
	}
	return strings.EqualFold(normalizedA, normalizedB)
}

func generatedServerName(base, addr string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = defaultTargetServer
	}

	suffix := fmt.Sprintf("-%08x", hashString(strings.ToLower(addr)))
	maxBaseLength := validation.QualifiedNameMaxLength - len(suffix)
	if maxBaseLength < 1 {
		maxBaseLength = 1
	}
	if len(base) > maxBaseLength {
		base = base[:maxBaseLength]
	}
	base = strings.Trim(base, "-._")
	if base == "" {
		base = defaultTargetServer
		if len(base) > maxBaseLength {
			base = base[:maxBaseLength]
		}
		base = strings.Trim(base, "-._")
		if base == "" {
			base = "at"
		}
	}

	name := base + suffix
	if validation.ValidServerName(name) {
		return name
	}

	fallback := fmt.Sprintf("%s-%08x", defaultTargetServer, hashString(strings.ToLower(addr)))
	if validation.ValidServerName(fallback) {
		return fallback
	}
	return defaultTargetServer
}

func hashString(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

type autoTransferServerInfo struct {
	name          string
	addr          net.Addr
	proxyProtocol bool
}

func newAutoTransferServerInfo(name string, addr net.Addr, proxyProtocol bool) proxy.ServerInfo {
	return &autoTransferServerInfo{
		name:          name,
		addr:          addr,
		proxyProtocol: proxyProtocol,
	}
}

func (s *autoTransferServerInfo) Name() string {
	return s.name
}

func (s *autoTransferServerInfo) Addr() net.Addr {
	return s.addr
}

func (s *autoTransferServerInfo) Dial(ctx context.Context, player proxy.Player) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.addr.String())
	if err != nil {
		return nil, err
	}
	if !s.proxyProtocol {
		return conn, nil
	}

	header, err := proxyProtocolHeader(player.RemoteAddr(), conn.RemoteAddr())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err = header.WriteTo(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("error writing proxy protocol header to backend: %w", err)
	}
	return conn, nil
}

func serverUsesProxyProtocol(server proxy.RegisteredServer) bool {
	if server == nil {
		return false
	}
	info, ok := server.ServerInfo().(*autoTransferServerInfo)
	return ok && info.proxyProtocol
}

func serverTargetKey(addr string, proxyProtocol bool) string {
	return fmt.Sprintf("%s|pp=%t", strings.TrimSpace(strings.ToLower(addr)), proxyProtocol)
}

func proxyProtocolHeader(srcAddr, destAddr net.Addr) (*proxyproto.Header, error) {
	src, err := normalizeProxyAddr(srcAddr)
	if err != nil {
		return nil, err
	}
	dst, err := normalizeProxyAddr(destAddr)
	if err != nil {
		return nil, err
	}

	header := proxyproto.HeaderProxyFromAddrs(0, src, dst)
	sourceAddr, sourceOK := header.SourceAddr.(*net.TCPAddr)
	destTCP, destOK := header.DestinationAddr.(*net.TCPAddr)
	if sourceOK && destOK {
		mismatch := len(sourceAddr.IP.To4()) == net.IPv4len && len(destTCP.IP) == net.IPv6len
		if mismatch {
			header.TransportProtocol = proxyproto.TCPv6
			sourceAddr.IP = sourceAddr.IP.To16()
			header.SourceAddr = sourceAddr
		}
	}
	return header, nil
}

func normalizeProxyAddr(addr net.Addr) (net.Addr, error) {
	if addr == nil {
		return nil, errors.New("nil address for proxy protocol header")
	}
	switch typed := addr.(type) {
	case *net.TCPAddr:
		return typed, nil
	case *net.UDPAddr:
		return &net.TCPAddr{IP: typed.IP, Port: typed.Port}, nil
	case *net.IPAddr:
		return &net.TCPAddr{IP: typed.IP, Port: 0}, nil
	case *net.UnixAddr:
		return nil, fmt.Errorf("unsupported unix address for proxy protocol header: %s", typed.String())
	default:
		host, port := netutil.HostPort(addr)
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %T: %s", addr, host)
		}
		return &net.TCPAddr{IP: ip, Port: int(port)}, nil
	}
}

func findLiteRouteIndex(routes []gateliteconfig.Route, matched *gateliteconfig.Route) int {
	if matched == nil {
		return -1
	}
	for i := range routes {
		if routes[i].Equal(matched) {
			return i
		}
	}
	return -1
}

func findLiteRouteIndexByHost(routes []gateliteconfig.Route, matchedHost string) int {
	matchedHost = strings.TrimSpace(strings.ToLower(matchedHost))
	if matchedHost == "" {
		return -1
	}
	for i := range routes {
		for _, host := range routes[i].Host {
			if strings.EqualFold(strings.TrimSpace(host), matchedHost) {
				return i
			}
		}
	}
	return -1
}

func normalizeRouteHostKey(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// substituteBackendParams replaces $1, $2, etc. in backend address templates.
func substituteBackendParams(template string, groups []string) string {
	if len(groups) == 0 {
		return template
	}

	result := template
	for i := len(groups); i >= 1; i-- {
		param := fmt.Sprintf("$%d", i)
		if i-1 < len(groups) {
			result = strings.ReplaceAll(result, param, groups[i-1])
		}
	}
	return result
}

// StatusResolver resolves and caches backend status pings per target address.
type StatusResolver struct {
	log     logr.Logger
	timeout time.Duration
	ttl     time.Duration

	mu      sync.Mutex
	entries map[string]*statusEntry
}

type StatusQuery struct {
	Addr          string
	ProxyProtocol bool
	SourceAddr    net.Addr
	VirtualHost   string
}

type statusEntry struct {
	cached    *javaping.ServerPing
	lastFetch time.Time

	fetching bool
	fetchCh  chan struct{}

	lastErr string
}

// NewStatusResolver creates a status resolver.
func NewStatusResolver(log logr.Logger, timeout, ttl time.Duration) *StatusResolver {
	return &StatusResolver{
		log:     log,
		timeout: timeout,
		ttl:     ttl,
		entries: make(map[string]*statusEntry),
	}
}

// Status resolves and returns backend status for a specific target.
func (r *StatusResolver) Status(ctx context.Context, query StatusQuery) (*javaping.ServerPing, error) {
	addr := strings.TrimSpace(query.Addr)
	if addr == "" {
		return nil, ErrNoAddressConfigured
	}

	_, normalizedAddr, err := parseTargetAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address %q: %w", addr, err)
	}
	query.Addr = normalizedAddr
	query.VirtualHost = normalizeVirtualHostString(query.VirtualHost)
	cacheKey := statusCacheKey(query)

	for {
		r.mu.Lock()
		entry := r.entries[cacheKey]
		if entry == nil {
			entry = &statusEntry{}
			r.entries[cacheKey] = entry
		}

		cached := entry.cached
		if cached != nil && time.Since(entry.lastFetch) < r.ttl {
			result := cloneServerPing(cached)
			r.mu.Unlock()
			return result, nil
		}

		if entry.fetching {
			ch := entry.fetchCh
			r.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		ch := make(chan struct{})
		entry.fetching = true
		entry.fetchCh = ch
		r.mu.Unlock()

		ping, fetchErr := r.fetch(ctx, query)

		r.mu.Lock()
		entry.fetching = false
		entry.fetchCh = nil
		if fetchErr == nil {
			entry.cached = ping
			entry.lastFetch = time.Now()
			entry.lastErr = ""
		} else if fetchErr.Error() != entry.lastErr {
			entry.lastErr = fetchErr.Error()
			r.log.V(1).Info("failed to ping backend", "address", query.Addr, "virtualHost", query.VirtualHost, "proxyProtocol", query.ProxyProtocol, "error", fetchErr)
		}
		r.mu.Unlock()
		close(ch)

		if fetchErr != nil {
			return nil, fetchErr
		}
		return cloneServerPing(ping), nil
	}
}

func (r *StatusResolver) fetch(ctx context.Context, query StatusQuery) (*javaping.ServerPing, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	data, _, err := pingAndListStatus(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ping %s: %w", query.Addr, err)
	}

	var resp javaping.ServerPing
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode ping response: %w", err)
	}

	if resp.Players == nil {
		resp.Players = &javaping.Players{}
	}

	return &resp, nil
}

func statusCacheKey(query StatusQuery) string {
	return fmt.Sprintf("%s|pp=%t|vh=%s", query.Addr, query.ProxyProtocol, normalizeRouteHostKey(query.VirtualHost))
}

func pingAndListStatus(ctx context.Context, query StatusQuery) ([]byte, time.Duration, error) {
	conn, err := dialStatusConn(ctx, query)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = conn.Close() }()

	host, port, err := statusHandshakeHostPort(query)
	if err != nil {
		return nil, 0, err
	}
	mcConn := mcnet.WrapConn(conn)

	if err := mcConn.WritePacket(pk.Marshal(
		0x00, // Handshake
		pk.VarInt(bot.ProtocolVersion),
		pk.String(host),
		pk.UnsignedShort(port),
		pk.Byte(1),
	)); err != nil {
		return nil, 0, fmt.Errorf("send handshake packet: %w", err)
	}

	if err := mcConn.WritePacket(pk.Marshal(packetid.ServerboundStatusRequest)); err != nil {
		return nil, 0, fmt.Errorf("send status request packet: %w", err)
	}

	var responsePacket pk.Packet
	if err := mcConn.ReadPacket(&responsePacket); err != nil {
		return nil, 0, fmt.Errorf("receive status response packet: %w", err)
	}
	var statusJSON pk.String
	if err := responsePacket.Scan(&statusJSON); err != nil {
		return nil, 0, fmt.Errorf("parse status response packet: %w", err)
	}

	startTime := time.Now()
	if err := mcConn.WritePacket(pk.Marshal(
		packetid.ServerboundStatusPingRequest,
		pk.Long(startTime.Unix()),
	)); err != nil {
		return nil, 0, fmt.Errorf("send ping request packet: %w", err)
	}

	if err := mcConn.ReadPacket(&responsePacket); err != nil {
		return nil, 0, fmt.Errorf("receive pong packet: %w", err)
	}
	var pong pk.Long
	if err := responsePacket.Scan(&pong); err != nil {
		return nil, 0, fmt.Errorf("parse pong packet: %w", err)
	}
	if pong != pk.Long(startTime.Unix()) {
		return nil, 0, fmt.Errorf("pong packet mismatch")
	}

	return []byte(statusJSON), time.Since(startTime), nil
}

func dialStatusConn(ctx context.Context, query StatusQuery) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", query.Addr)
	if err != nil {
		return nil, err
	}

	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	if !query.ProxyProtocol {
		return conn, nil
	}

	sourceAddr := query.SourceAddr
	if sourceAddr == nil {
		sourceAddr = conn.LocalAddr()
	}
	header, err := proxyProtocolHeader(sourceAddr, conn.RemoteAddr())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err = header.WriteTo(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write proxy protocol header: %w", err)
	}
	return conn, nil
}

func statusHandshakeHostPort(query StatusQuery) (host string, port uint16, err error) {
	backendHost, backendPort, splitErr := net.SplitHostPort(query.Addr)
	if splitErr != nil {
		return "", 0, splitErr
	}
	parsedPort, parseErr := strconv.ParseUint(backendPort, 10, 16)
	if parseErr != nil {
		return "", 0, parseErr
	}

	host = strings.TrimSpace(query.VirtualHost)
	if host == "" {
		host = backendHost
	}
	return host, uint16(parsedPort), nil
}

func cloneServerPing(src *javaping.ServerPing) *javaping.ServerPing {
	if src == nil {
		return nil
	}

	cp := *src
	if src.Description != nil {
		desc := *src.Description
		cp.Description = &desc
	}
	if src.Players != nil {
		players := *src.Players
		if src.Players.Sample != nil {
			players.Sample = append([]javaping.SamplePlayer(nil), src.Players.Sample...)
		}
		cp.Players = &players
	}
	if src.ModInfo != nil {
		info := *src.ModInfo
		if src.ModInfo.Mods != nil {
			mods := make([]modinfo.Mod, len(src.ModInfo.Mods))
			copy(mods, src.ModInfo.Mods)
			info.Mods = mods
		}
		cp.ModInfo = &info
	}

	return &cp
}
