package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/query"
	"github.com/gotd/td/telegram/query/messages"
	"github.com/gotd/td/tg"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/tgdrive/teldrive/internal/api"
	"github.com/tgdrive/teldrive/internal/config"
	"github.com/tgdrive/teldrive/internal/crypt"
	"github.com/tgdrive/teldrive/internal/database"
	"github.com/tgdrive/teldrive/internal/tgc"
	"github.com/tgdrive/teldrive/internal/utils"
	"github.com/tgdrive/teldrive/pkg/models"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type file struct {
	ID        string
	Name      string
	Size      int64
	Encrypted bool
	Parts     datatypes.JSONSlice[api.Part]
}

type exportFile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type channelExport struct {
	ChannelID int64        `json:"channel_id"`
	Timestamp string       `json:"timestamp"`
	FileCount int          `json:"file_count"`
	Files     []exportFile `json:"files"`
}

type channelProcessor struct {
	id             int64
	files          []file
	missingFiles   []file
	orphanMessages []int
	totalCount     int64
	mp             *pterm.MultiPrinter
	pb             *pterm.ProgressbarPrinter
	channelExport  *channelExport
	client         *telegram.Client
	ctx            context.Context
	db             *gorm.DB
	userId         int64
	dryRun         bool
	cfg            *config.TGConfig
	session        string
}

func NewCheckCmd() *cobra.Command {
	var cfg config.ServerCmdConfig
	loader := config.NewConfigLoader()
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check and purge incomplete files in Telegram channels",
		Long: `Check the integrity of files stored in Telegram channels by comparing database records
with actual Telegram messages. Identifies and removes missing file parts and orphan messages.

Examples:
  # Preview issues without making changes (dry-run)
  teldrive check --user alice --dry-run

  # Check, clean and export missing files to a custom file
  teldrive check --export-file missing_files.json

  # Clean missing files and orphan messages
  teldrive check

  # Concurrent processing
  teldrive check --concurrent 8`,
		Run: func(cmd *cobra.Command, args []string) {
			runCheckCmd(cmd, &cfg)
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := loader.Load(cmd, &cfg); err != nil {
				return err
			}
			if err := checkRequiredCheckFlags(&cfg); err != nil {
				return err
			}
			return nil
		},
	}
	loader.RegisterFlags(cmd.Flags())
	cmd.Flags().String("export-file", "results.json", "Path for exported JSON file")
	cmd.Flags().Bool("dry-run", false, "Simulate check/clean process without making changes")
	cmd.Flags().String("user", "", "Telegram username to check (prompts if not specified)")
	cmd.Flags().Int("concurrent", 4, "Number of concurrent channel processing")
	return cmd
}

func checkRequiredCheckFlags(cfg *config.ServerCmdConfig) error {
	var missingFields []string
	if cfg.DB.DataSource == "" {
		missingFields = append(missingFields, "db-data-source")
	}
	if len(missingFields) > 0 {
		return fmt.Errorf("required configuration values not set: %s", strings.Join(missingFields, ", "))
	}
	return nil
}

func selectUser(user string, users []models.User) (*models.User, error) {
	if user != "" {
		res := utils.Filter(users, func(u models.User) bool {
			return u.UserName == user
		})
		if len(res) == 0 {
			return nil, fmt.Errorf("invalid user name: %s", user)
		}
		return &res[0], nil
	}

	var options []string
	for _, u := range users {
		options = append(options, u.UserName)
	}

	selected, err := pterm.DefaultInteractiveSelect.
		WithDefaultText("Select User").
		WithOptions(options).
		Show()
	if err != nil {
		return nil, err
	}

	for i := range users {
		if users[i].UserName == selected {
			return &users[i], nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (cp *channelProcessor) updateStatus(status string, value int64) {
	if cp.pb != nil {
		current := cp.pb.Current
		if int(value) > current {
			cp.pb.Add(int(value) - current)
		}
		cp.pb.UpdateTitle(fmt.Sprintf("Channel %d: %s", cp.id, status))
	}
}

func (cp *channelProcessor) process() error {
	cp.updateStatus("Loading files", 0)
	files, err := cp.loadFiles()
	if err != nil {
		return fmt.Errorf("failed to load files for channel %d: %w", cp.id, err)
	}
	cp.files = files

	if len(cp.files) == 0 {
		cp.updateStatus("No files found", 100)
		return nil
	}

	cp.updateStatus("Loading messages from Telegram", 0)
	msgs, total, err := cp.loadChannelMessages()
	if err != nil {
		return fmt.Errorf("failed to load messages for channel %d: %w", cp.id, err)
	}

	if total == 0 && len(msgs) == 0 {
		cp.updateStatus("No messages found", 100)
		return nil
	}
	if len(msgs) < total {
		return fmt.Errorf("channel %d: found %d messages out of %d", cp.id, len(msgs), total)
	}

	cp.updateStatus("Processing messages and parts", 0)
	uploadPartIds := []int{}
	if err := cp.db.Model(&models.Upload{}).
		Where("user_id = ?", cp.userId).
		Where("channel_id = ?", cp.id).
		Pluck("part_id", &uploadPartIds).Error; err != nil {
		return fmt.Errorf("failed to query uploads for channel %d: %w", cp.id, err)
	}

	uploadPartMap := make(map[int]bool)
	for _, partID := range uploadPartIds {
		uploadPartMap[partID] = true
	}

	msgMap := make(map[int]int64)
	for _, m := range msgs {
		id := m.Msg.GetID()
		_, ok := uploadPartMap[id]
		if id > 0 && !ok {
			doc, ok := m.Document()
			if !ok {
				msgMap[id] = 0
			} else {
				msgMap[id] = doc.GetSize()
			}
		}
	}

	cp.updateStatus("Checking file integrity", 0)

	allPartIDs := make(map[int]bool)

	for _, f := range cp.files {
		size := int64(0)
		for _, p := range f.Parts {
			if p.ID != 0 {
				allPartIDs[p.ID] = true
			}
			_, ok := msgMap[p.ID]
			if !ok {
				cp.missingFiles = append(cp.missingFiles, f)
				break
			}
			if f.Encrypted {
				d, _ := crypt.DecryptedSize(msgMap[p.ID])
				size += d
			} else {
				size += msgMap[p.ID]
			}
		}
		if size != f.Size {
			cp.missingFiles = append(cp.missingFiles, f)
		}
	}

	if len(allPartIDs) == 0 {
		cp.updateStatus("No parts found", 100)
		return nil
	}

	for msgID := range msgMap {
		_, ok := allPartIDs[msgID]
		if !ok {
			cp.orphanMessages = append(cp.orphanMessages, msgID)
		}
	}

	if len(cp.missingFiles) > 0 {
		cp.channelExport = &channelExport{
			ChannelID: cp.id,
			Timestamp: time.Now().Format(time.RFC3339),
			FileCount: len(cp.missingFiles),
			Files:     make([]exportFile, 0, len(cp.missingFiles)),
		}

		for _, f := range cp.missingFiles {
			cp.channelExport.Files = append(cp.channelExport.Files, exportFile{
				ID:   f.ID,
				Name: f.Name,
			})
		}

		if cp.dryRun {
			// dry run logic
		} else {
			cp.updateStatus("Cleaning files", 0)
			err = cp.db.Exec("call teldrive.delete_files_bulk($1 , $2)",
				utils.Map(cp.missingFiles, func(f file) string { return f.ID }), cp.userId).Error
			if err != nil {
				return fmt.Errorf("failed to clean files for channel %d: %w", cp.id, err)
			}
		}

	}

	if len(cp.orphanMessages) > 0 {
		if cp.dryRun {
			// dry run logic
		} else {
			cp.updateStatus("Cleaning orphan messages", 0)
			err = cp.initClient()
			if err != nil {
				return err
			}
			err = tgc.DeleteMessages(cp.ctx, cp.client, cp.id, cp.orphanMessages)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (cp *channelProcessor) loadFiles() ([]file, error) {
	var files []file
	const batchSize = 1000
	var totalFiles int64
	var lastID string

	if err := cp.db.Model(&models.File{}).
		Where("user_id = ?", cp.userId).
		Where("channel_id = ?", cp.id).
		Where("type = ?", "file").
		Count(&totalFiles).Error; err != nil {
		return nil, err
	}

	if totalFiles == 0 {
		return nil, nil
	}

	processed := int64(0)
	for {
		var batch []file
		query := cp.db.WithContext(cp.ctx).Model(&models.File{}).
			Where("user_id = ?", cp.userId).
			Where("channel_id = ?", cp.id).
			Where("type = ?", "file").
			Order("id").
			Limit(batchSize)

		if lastID != "" {
			query = query.Where("id > ?", lastID)
		}

		result := query.Scan(&batch)
		if result.Error != nil {
			return nil, result.Error
		}

		if len(batch) == 0 {
			break
		}

		files = append(files, batch...)
		processed += int64(len(batch))

		lastID = batch[len(batch)-1].ID
		progress := (float64(processed) / float64(totalFiles)) * 100
		cp.updateStatus(fmt.Sprintf("Loading files: %d/%d", processed, totalFiles), int64(progress))
		if len(batch) < batchSize {
			break
		}
	}

	return files, nil
}

func (cp *channelProcessor) initClient() error {
	middlewares := tgc.NewMiddleware(cp.cfg, tgc.WithFloodWait(), tgc.WithRateLimit())
	client, err := tgc.AuthClient(cp.ctx, cp.cfg, cp.session, middlewares...)
	if err != nil {
		return fmt.Errorf("failed to create client %w", err)
	}
	cp.client = client
	return nil
}

func (cp *channelProcessor) loadChannelMessages() (msgs []messages.Elem, total int, err error) {
	err = cp.initClient()
	if err != nil {
		return nil, 0, err
	}
	err = tgc.RunWithAuth(cp.ctx, cp.client, "", func(ctx context.Context) error {
		var channel *tg.InputChannel
		channel, err = tgc.GetChannelById(ctx, cp.client.API(), cp.id)
		if err != nil {
			return err
		}

		q := query.NewQuery(cp.client.API()).Messages().GetHistory(&tg.InputPeerChannel{
			ChannelID:  cp.id,
			AccessHash: channel.AccessHash,
		})

		msgiter := messages.NewIterator(q, 100)
		total, err = msgiter.Total(ctx)
		if err != nil {
			return err
		}

		processed := 0
		for msgiter.Next(ctx) {
			msg := msgiter.Value()
			msgs = append(msgs, msg)
			processed++

			if processed%100 == 0 {
				progress := (float64(processed) / float64(total)) * 100
				cp.updateStatus(fmt.Sprintf("Loading messages: %d/%d", processed, total), int64(progress))
			}
		}
		return nil
	})
	return msgs, total, err
}

func runCheckCmd(cmd *cobra.Command, cfg *config.ServerCmdConfig) {

	ctx := cmd.Context()

	cfg.DB.LogLevel = "fatal"
	db, err := database.NewDatabase(ctx, &cfg.DB, zap.NewNop())
	if err != nil {
		pterm.Error.Println("failed to connect to database", err)
		os.Exit(1)
	}

	users := []models.User{}
	if err := db.Model(&models.User{}).Find(&users).Error; err != nil {
		pterm.Error.Println("failed to retrieve users from database", err)
		os.Exit(1)
	}

	userName, _ := cmd.Flags().GetString("user")
	user, err := selectUser(userName, users)
	if err != nil {
		pterm.Error.Println("failed to select user", err)
		os.Exit(1)
	}

	session := models.Session{}
	if err := db.Model(&models.Session{}).
		Where("user_id = ?", user.UserId).
		Order("created_at desc").
		First(&session).Error; err != nil {
		pterm.Error.Println("failed to get user session - ensure user has logged in", err)
		os.Exit(1)
	}

	channelIds := []int64{}
	if err := db.Model(&models.Channel{}).
		Where("user_id = ?", user.UserId).
		Pluck("channel_id", &channelIds).Error; err != nil {
		pterm.Error.Println("failed to get user channels", err)
		os.Exit(1)
	}

	if len(channelIds) == 0 {
		pterm.Error.Println("no channels found for user - ensure channels are configured")
		os.Exit(1)
	}

	exportFile, _ := cmd.Flags().GetString("export-file")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	concurrent, _ := cmd.Flags().GetInt("concurrent")

	if dryRun {
		pterm.Info.Println("running in dry-run mode - no changes will be made")
	}

	multi := pterm.DefaultMultiPrinter
	_, _ = multi.Start()

	var channelExports []channelExport
	var mutex sync.Mutex
	var totalFiles, totalMissing, totalOrphans, totalCleanedFiles, totalCleanedOrphans int

	g, ctx := errgroup.WithContext(ctx)

	g.SetLimit(concurrent)

	for _, id := range channelIds {

		g.Go(func() error {

			pb, _ := pterm.DefaultProgressbar.
				WithTotal(100).
				WithWriter(multi.NewWriter()).
				WithTitle(fmt.Sprintf("Channel %d: Initializing", id)).
				Start()

			processor := &channelProcessor{
				id:         id,
				ctx:        ctx,
				cfg:        &cfg.TG,
				session:    session.Session,
				db:         db,
				userId:     user.UserId,
				dryRun:     dryRun,
				mp:         &multi,
				pb:         pb,
				totalCount: 100,
			}

			if err := processor.process(); err != nil {
				return err
			}

			if processor.channelExport != nil {
				mutex.Lock()
				channelExports = append(channelExports, *processor.channelExport)
				totalMissing += len(processor.missingFiles)
				totalOrphans += len(processor.orphanMessages)
				mutex.Unlock()
			}
			mutex.Lock()
			totalFiles += len(processor.files)
			if !dryRun {
				totalCleanedFiles += len(processor.missingFiles)
				totalCleanedOrphans += len(processor.orphanMessages)
			}
			mutex.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		pterm.Error.Println("one or more channels failed to process - check logs for details")
		os.Exit(1)
	}

	_, _ = multi.Stop()

	if !dryRun && len(channelExports) > 0 {
		jsonData, err := json.MarshalIndent(channelExports, "", "    ")
		if err != nil {
			pterm.Error.Println("failed to generate JSON export", err)
			return
		}

		err = os.WriteFile(exportFile, jsonData, 0644)
		if err != nil {
			pterm.Error.Println("failed to write export file", err)
			return
		}

		pterm.Info.Println("exported incomplete files", pterm.Sprint(map[string]interface{}{"file": exportFile, "count": totalMissing}))
	}

	pterm.DefaultHeader.WithFullWidth().Println("Check Summary")

	data := [][]string{
		{"Metric", "Value"},
		{"Channels Processed", fmt.Sprint(len(channelIds))},
		{"Total Files Checked", fmt.Sprint(totalFiles)},
		{"Missing Files", fmt.Sprint(totalMissing)},
		{"Orphan Messages", fmt.Sprint(totalOrphans)},
	}

	if dryRun {
		data = append(data, []string{"Would Clean Files", fmt.Sprint(totalMissing)})
		data = append(data, []string{"Would Clean Orphans", fmt.Sprint(totalOrphans)})
	} else {
		data = append(data, []string{"Cleaned Files", fmt.Sprint(totalCleanedFiles)})
		data = append(data, []string{"Cleaned Orphans", fmt.Sprint(totalCleanedOrphans)})
	}

	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(data).Render()
}
