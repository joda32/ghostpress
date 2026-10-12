package output

import "ghostpress/model"

type Formatter interface {
	Banner()
	ScanStarted(target model.TargetInfo)
	InterestingFindings(findings []model.InterestingFinding)
	Version(version *model.WPVersion)
	MainTheme(theme *model.Theme)
	Plugins(plugins []model.Plugin)
	Themes(themes []model.Theme)
	Users(users []model.User)
	ConfigBackups(backups []string)
	DBExports(exports []string)
	TimThumbs(paths []string)
	Media(media []model.Media)
	PasswordResults(results []model.PasswordResult)
	ScanFinished(result *model.ScanResult)
	Error(msg string)
}
