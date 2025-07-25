package utils

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/inconshreveable/log15"
	"github.com/parnurzeal/gorequest"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

// GetDefaultLogDir :
func GetDefaultLogDir() string {
	defaultLogDir := "/var/log/go-kev"
	if runtime.GOOS == "windows" {
		defaultLogDir = filepath.Join(os.Getenv("APPDATA"), "go-kev")
	}
	return defaultLogDir
}

// SetLogger :
func SetLogger(logToFile bool, logDir string, debug, logJSON bool) error {
	stderrHandler := log15.StderrHandler
	logFormat := log15.LogfmtFormat()
	if logJSON {
		logFormat = log15.JsonFormatEx(false, true)
		stderrHandler = log15.StreamHandler(os.Stderr, logFormat)
	}

	lvlHandler := log15.LvlFilterHandler(log15.LvlInfo, stderrHandler)
	if debug {
		lvlHandler = log15.LvlFilterHandler(log15.LvlDebug, stderrHandler)
	}

	var handler log15.Handler
	if logToFile {
		if _, err := os.Stat(logDir); err != nil {
			if os.IsNotExist(err) {
				if err := os.Mkdir(logDir, 0700); err != nil {
					return xerrors.Errorf("Failed to create log directory. err: %w", err)
				}
			} else {
				return xerrors.Errorf("Failed to check log directory. err: %w", err)
			}
		}

		logPath := filepath.Join(logDir, "go-kev.log")
		if _, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err != nil {
			return xerrors.Errorf("Failed to open a log file. err: %w", err)
		}
		handler = log15.MultiHandler(
			log15.Must.FileHandler(logPath, logFormat),
			lvlHandler,
		)
	} else {
		handler = lvlHandler
	}
	log15.Root().SetHandler(handler)
	return nil
}

// FetchURL returns HTTP response body
func FetchURL(url string) ([]byte, error) {
	httpProxy := viper.GetString("http-proxy")

	resp, body, errs := gorequest.New().Proxy(httpProxy).Get(url).Type("text").EndBytes()
	if len(errs) > 0 || resp == nil || resp.StatusCode != 200 {
		return nil, xerrors.Errorf("HTTP error. url: %s, err: %v", url, errs)
	}
	return body, nil
}

// ToPtr returns a pointer to the value passed in
func ToPtr[T any](v T) *T {
	return &v
}
