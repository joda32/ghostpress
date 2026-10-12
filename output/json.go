package output

import (
	"encoding/json"
	"fmt"
	"os"

	"ghostpress/model"
)

type JSONFormatter struct {
	result *model.ScanResult
	w      *os.File
}

func NewJSON(output *os.File) *JSONFormatter {
	if output == nil {
		output = os.Stdout
	}
	return &JSONFormatter{
		result: &model.ScanResult{},
		w:      output,
	}
}

func (f *JSONFormatter) Banner() {}

func (f *JSONFormatter) ScanStarted(target model.TargetInfo) {
	f.result.Target = target
}

func (f *JSONFormatter) InterestingFindings(findings []model.InterestingFinding) {
	f.result.InterestingFindings = findings
}

func (f *JSONFormatter) Version(version *model.WPVersion) {
	f.result.Version = version
}

func (f *JSONFormatter) MainTheme(theme *model.Theme) {
	f.result.MainTheme = theme
}

func (f *JSONFormatter) Plugins(plugins []model.Plugin) {
	f.result.Plugins = plugins
}

func (f *JSONFormatter) Themes(themes []model.Theme) {
	f.result.Themes = themes
}

func (f *JSONFormatter) Users(users []model.User) {
	f.result.Users = users
}

func (f *JSONFormatter) ConfigBackups(backups []string) {
	f.result.ConfigBackups = backups
}

func (f *JSONFormatter) DBExports(exports []string) {
	f.result.DBExports = exports
}

func (f *JSONFormatter) TimThumbs(paths []string) {
	f.result.TimThumbs = paths
}

func (f *JSONFormatter) Media(media []model.Media) {
	f.result.Media = media
}

func (f *JSONFormatter) PasswordResults(results []model.PasswordResult) {
	f.result.PasswordResults = results
}

func (f *JSONFormatter) ScanFinished(result *model.ScanResult) {
	f.result.StartTime = result.StartTime
	f.result.EndTime = result.EndTime
	f.result.RequestsDone = result.RequestsDone
	f.result.DataSent = result.DataSent
	f.result.DataReceived = result.DataReceived
	f.result.Error = result.Error

	data, err := json.MarshalIndent(f.result, "", "  ")
	if err != nil {
		fmt.Fprintf(f.w, `{"error": "failed to marshal results: %s"}`, err)
		return
	}
	f.w.Write(data)
	f.w.Write([]byte("\n"))
}

func (f *JSONFormatter) Error(msg string) {
	f.result.Error = msg
}
