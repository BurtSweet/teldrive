package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/knadh/koanf/maps"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tgdrive/teldrive/internal/duration"
)

type ServerCmdConfig struct {
	Server   ServerConfig
	Log      LoggingConfig
	JWT      JWTConfig
	DB       DBConfig
	TG       TGConfig
	CronJobs CronJobConfig
	Cache    CacheConfig
}

type ServerConfig struct {
	Port             int
	GracefulShutdown time.Duration
	EnablePprof      bool
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
}

type CacheConfig struct {
	MaxSize   int
	RedisAddr string
	RedisPass string
}

type LoggingConfig struct {
	Level string
	File  string
}

type JWTConfig struct {
	Secret       string `validate:"required"`
	SessionTime  time.Duration
	AllowedUsers []string
}

type DBPool struct {
	Enable             bool
	MaxOpenConnections int
	MaxIdleConnections int
	MaxLifetime        time.Duration
}
type DBConfig struct {
	DataSource  string `validate:"required"`
	PrepareStmt bool
	LogLevel    string
	Pool        DBPool
}

type CronJobConfig struct {
	Enable               bool
	LockerInstance       string
	CleanFilesInterval   time.Duration
	CleanUploadsInterval time.Duration
	FolderSizeInterval   time.Duration
}

type TGStream struct {
	Concurrency  int
	Buffers      int
	ChunkTimeout time.Duration
}

type TGUpload struct {
	EncryptionKey string `validate:"required"`
	Threads       int
	MaxRetries    int
	Retention     time.Duration
}
type TGConfig struct {
	RateLimit         bool
	RateBurst         int
	Rate              int
	Ntp               bool
	Proxy             string
	ReconnectTimeout  time.Duration
	PoolSize          int
	EnableLogging     bool
	AppId             int
	AppHash           string
	DeviceModel       string
	SystemVersion     string
	AppVersion        string
	LangCode          string
	SystemLangCode    string
	LangPack          string
	SessionInstance   string
	AutoChannelCreate bool
	ChannelLimit      int64
	Uploads           TGUpload
	Stream            TGStream
}

type ConfigLoader struct {
	k       *koanf.Koanf
	flagMap map[string]string
}

func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{
		k:       koanf.New("."),
		flagMap: make(map[string]string),
	}
}

// customFlagProvider loads flags from a pflag.FlagSet.
type customFlagProvider struct {
	f           *pflag.FlagSet
	flagMap     map[string]string
	onlyChanged bool
	defaults    bool
}

func (p *customFlagProvider) Read() (map[string]interface{}, error) {
	m := make(map[string]interface{})
	p.f.VisitAll(func(f *pflag.Flag) {
		if p.defaults && f.Changed {
			return
		}
		if p.onlyChanged && !f.Changed {
			return
		}

		var key string
		if mapped, ok := p.flagMap[f.Name]; ok {
			key = mapped
		} else {
			// Fallback: simple dash replacement if not mapped (should not happen if registered correctly)
			key = strings.ReplaceAll(f.Name, "-", ".")
		}

		// Handle slices
		if sliceVal, ok := f.Value.(pflag.SliceValue); ok {
			m[key] = sliceVal.GetSlice()
		} else {
			m[key] = f.Value.String()
		}
	})
	return maps.Unflatten(m, "."), nil
}

func (p *customFlagProvider) ReadBytes() ([]byte, error) {
	return nil, nil
}

type unflattenProvider struct {
	p     koanf.Provider
	delim string
}

func (p *unflattenProvider) Read() (map[string]interface{}, error) {
	m, err := p.p.Read()
	if err != nil {
		return nil, err
	}
	return maps.Unflatten(m, p.delim), nil
}

func (p *unflattenProvider) ReadBytes() ([]byte, error) {
	return nil, nil
}

func (cl *ConfigLoader) Load(cmd *cobra.Command, cfg *ServerCmdConfig) error {

	cfgFile := cmd.Flags().Lookup("config").Value.String()
	var parser koanf.Parser

	if cfgFile != "" {
		if strings.HasSuffix(cfgFile, ".yaml") || strings.HasSuffix(cfgFile, ".yml") {
			parser = yaml.Parser()
		} else {
			parser = toml.Parser()
		}
	} else {
		parser = toml.Parser()
	}

	// 1. Load defaults from flags
	if err := cl.k.Load(&customFlagProvider{f: cmd.Flags(), flagMap: cl.flagMap, defaults: true}, nil); err != nil {
		return err
	}

	// 2. Load config file
	if cfgFile != "" {
		if err := cl.k.Load(file.Provider(cfgFile), parser); err != nil {
			return fmt.Errorf("error reading config file: %v", err)
		}
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("error getting home directory: %v", err)
		}
		paths := []string{
			filepath.Join(home, ".teldrive", "config.toml"),
			"config.toml",
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				if err := cl.k.Load(file.Provider(path), toml.Parser()); err != nil {
					return fmt.Errorf("error reading config file: %v", err)
				}
				break
			}
		}
	}

	// 3. Load environment variables
	if err := cl.k.Load(&unflattenProvider{
		p: env.Provider("TELDRIVE_", ".", func(s string) string {
			return strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(s, "TELDRIVE_")), "_", ".")
		}),
		delim: ".",
	}, nil); err != nil {
		return err
	}

	// 4. Load explicit flags
	if err := cl.k.Load(&customFlagProvider{f: cmd.Flags(), flagMap: cl.flagMap, onlyChanged: true}, nil); err != nil {
		return err
	}

	return cl.populate(cfg)
}

func (cl *ConfigLoader) getDuration(key string) time.Duration {
	val := cl.k.String(key)
	d, _ := duration.ParseDuration(val)
	return d
}

func (cl *ConfigLoader) populate(cfg *ServerCmdConfig) error {
	k := cl.k

	cfg.Server.Port = k.Int("server.port")
	cfg.Server.GracefulShutdown = cl.getDuration("server.graceful-shutdown")
	cfg.Server.EnablePprof = k.Bool("server.enable-pprof")
	cfg.Server.ReadTimeout = cl.getDuration("server.read-timeout")
	cfg.Server.WriteTimeout = cl.getDuration("server.write-timeout")

	cfg.Log.Level = k.String("log.level")
	cfg.Log.File = k.String("log.file")

	cfg.Cache.MaxSize = k.Int("cache.max-size")
	cfg.Cache.RedisAddr = k.String("cache.redis-addr")
	cfg.Cache.RedisPass = k.String("cache.redis-pass")

	cfg.JWT.Secret = k.String("jwt.secret")
	cfg.JWT.SessionTime = cl.getDuration("jwt.session-time")
	cfg.JWT.AllowedUsers = k.Strings("jwt.allowed-users")

	cfg.DB.DataSource = k.String("db.data-source")
	cfg.DB.PrepareStmt = k.Bool("db.prepare-stmt")
	cfg.DB.LogLevel = k.String("db.log-level")
	cfg.DB.Pool.Enable = k.Bool("db.pool.enable")
	cfg.DB.Pool.MaxOpenConnections = k.Int("db.pool.max-open-connections")
	cfg.DB.Pool.MaxIdleConnections = k.Int("db.pool.max-idle-connections")
	cfg.DB.Pool.MaxLifetime = cl.getDuration("db.pool.max-lifetime")

	cfg.CronJobs.Enable = k.Bool("cronjobs.enable")
	cfg.CronJobs.LockerInstance = k.String("cronjobs.locker-instance")
	cfg.CronJobs.CleanFilesInterval = cl.getDuration("cronjobs.clean-files-interval")
	cfg.CronJobs.CleanUploadsInterval = cl.getDuration("cronjobs.clean-uploads-interval")
	cfg.CronJobs.FolderSizeInterval = cl.getDuration("cronjobs.folder-size-interval")

	cfg.TG.RateLimit = k.Bool("tg.rate-limit")
	cfg.TG.RateBurst = k.Int("tg.rate-burst")
	cfg.TG.Rate = k.Int("tg.rate")
	cfg.TG.Ntp = k.Bool("tg.ntp")
	cfg.TG.Proxy = k.String("tg.proxy")
	cfg.TG.ReconnectTimeout = cl.getDuration("tg.reconnect-timeout")
	cfg.TG.PoolSize = k.Int("tg.pool-size")
	cfg.TG.EnableLogging = k.Bool("tg.enable-logging")
	cfg.TG.AppId = k.Int("tg.app-id")
	cfg.TG.AppHash = k.String("tg.app-hash")
	cfg.TG.DeviceModel = k.String("tg.device-model")
	cfg.TG.SystemVersion = k.String("tg.system-version")
	cfg.TG.AppVersion = k.String("tg.app-version")
	cfg.TG.LangCode = k.String("tg.lang-code")
	cfg.TG.SystemLangCode = k.String("tg.system-lang-code")
	cfg.TG.LangPack = k.String("tg.lang-pack")
	cfg.TG.SessionInstance = k.String("tg.session-instance")
	cfg.TG.AutoChannelCreate = k.Bool("tg.auto-channel-create")
	cfg.TG.ChannelLimit = k.Int64("tg.channel-limit")

	cfg.TG.Uploads.EncryptionKey = k.String("tg.uploads.encryption-key")
	cfg.TG.Uploads.Threads = k.Int("tg.uploads.threads")
	cfg.TG.Uploads.MaxRetries = k.Int("tg.uploads.max-retries")
	cfg.TG.Uploads.Retention = cl.getDuration("tg.uploads.retention")

	cfg.TG.Stream.Concurrency = k.Int("tg.stream.concurrency")
	cfg.TG.Stream.Buffers = k.Int("tg.stream.buffers")
	cfg.TG.Stream.ChunkTimeout = cl.getDuration("tg.stream.chunk-timeout")

	return nil
}

func (cl *ConfigLoader) Validate(cfg any) error {
	validate := validator.New()
	return validate.Struct(cfg)
}

func (cl *ConfigLoader) register(flags *pflag.FlagSet, key string, value interface{}, usage string) {
	name := strings.ReplaceAll(key, ".", "-")
	cl.flagMap[name] = key
	switch v := value.(type) {
	case int:
		flags.Int(name, v, usage)
	case int64:
		flags.Int64(name, v, usage)
	case string:
		flags.String(name, v, usage)
	case bool:
		flags.Bool(name, v, usage)
	case time.Duration:
		flags.Duration(name, v, usage)
	case []string:
		flags.StringSlice(name, v, usage)
	}
}

func (cl *ConfigLoader) RegisterFlags(flags *pflag.FlagSet) {
	flags.StringP("config", "c", "", "Config file path (default $HOME/.teldrive/config.toml)")

	// Server
	cl.register(flags, "server.port", 8080, "HTTP port for the server to listen on")
	cl.register(flags, "server.graceful-shutdown", 10*time.Second, "Grace period for server shutdown")
	cl.register(flags, "server.enable-pprof", false, "Enable pprof debugging endpoints")
	cl.register(flags, "server.read-timeout", time.Hour, "Maximum duration for reading entire request")
	cl.register(flags, "server.write-timeout", time.Hour, "Maximum duration for writing response")

	// Cache
	cl.register(flags, "cache.max-size", 10485760, "Maximum cache size in bytes")
	cl.register(flags, "cache.redis-addr", "", "Redis server address")
	cl.register(flags, "cache.redis-pass", "", "Redis server password")

	// Log
	cl.register(flags, "log.level", "info", "Logging level (debug, info, warn, error)")
	cl.register(flags, "log.file", "", "Log file path, if empty logs to stdout")

	// JWT
	cl.register(flags, "jwt.secret", "", "JWT signing secret key")
	cl.register(flags, "jwt.session-time", 30*24*time.Hour, "JWT token validity duration")
	cl.register(flags, "jwt.allowed-users", []string{}, "List of allowed usernames")

	// DB
	cl.register(flags, "db.data-source", "", "Database connection string")
	cl.register(flags, "db.prepare-stmt", true, "Use prepared statements")
	cl.register(flags, "db.log-level", "error", "Database logging level")
	cl.register(flags, "db.pool.enable", true, "Enable connection pooling")
	cl.register(flags, "db.pool.max-open-connections", 25, "Maximum number of open connections")
	cl.register(flags, "db.pool.max-idle-connections", 25, "Maximum number of idle connections")
	cl.register(flags, "db.pool.max-lifetime", 10*time.Minute, "Maximum connection lifetime")

	// CronJobs
	cl.register(flags, "cronjobs.enable", true, "Enable scheduled background jobs")
	cl.register(flags, "cronjobs.locker-instance", "cron-locker", "Distributed unique cron locker name")
	cl.register(flags, "cronjobs.clean-files-interval", time.Hour, "Interval for cleaning expired files")
	cl.register(flags, "cronjobs.clean-uploads-interval", 12*time.Hour, "Interval for cleaning incomplete uploads")
	cl.register(flags, "cronjobs.folder-size-interval", 2*time.Hour, "Interval for updating folder sizes")

	// TG
	cl.register(flags, "tg.rate-limit", true, "Enable rate limiting for API calls")
	cl.register(flags, "tg.rate-burst", 5, "Maximum burst size for rate limiting")
	cl.register(flags, "tg.rate", 100, "Rate limit in requests per minute")
	cl.register(flags, "tg.ntp", false, "Use NTP for time synchronization")
	cl.register(flags, "tg.proxy", "", "HTTP/SOCKS5 proxy URL")
	cl.register(flags, "tg.reconnect-timeout", 5*time.Minute, "Client reconnection timeout")
	cl.register(flags, "tg.pool-size", 8, "Session pool size")
	cl.register(flags, "tg.enable-logging", false, "Enable Telegram client logging")
	cl.register(flags, "tg.app-id", 2496, "Telegram app ID")
	cl.register(flags, "tg.app-hash", "8da85b0d5bfe62527e5b244c209159c3", "Telegram app hash")
	cl.register(flags, "tg.device-model", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0", "Device model")
	cl.register(flags, "tg.system-version", "Win32", "System version")
	cl.register(flags, "tg.app-version", "6.1.4 K", "App version")
	cl.register(flags, "tg.lang-code", "en", "Language code")
	cl.register(flags, "tg.system-lang-code", "en-US", "System language code")
	cl.register(flags, "tg.lang-pack", "webk", "Language pack")
	cl.register(flags, "tg.session-instance", "teldrive", "Bot Sessions Instance Name")
	cl.register(flags, "tg.auto-channel-create", true, "Auto Create Channel")
	cl.register(flags, "tg.channel-limit", int64(500000), "Channel message limit before auto channel creation")

	// TG Uploads
	cl.register(flags, "tg.uploads.encryption-key", "", "Encryption key for uploads")
	cl.register(flags, "tg.uploads.threads", 8, "Number of upload threads")
	cl.register(flags, "tg.uploads.max-retries", 10, "Maximum upload retry attempts")
	cl.register(flags, "tg.uploads.retention", 7*24*time.Hour, "Upload retention period")

	// TG Stream
	cl.register(flags, "tg.stream.concurrency", 1, "Number of concurrent threads for concurrent reader")
	cl.register(flags, "tg.stream.buffers", 8, "Number of stream buffers")
	cl.register(flags, "tg.stream.chunk-timeout", 30*time.Second, "Chunk download timeout")
}
