package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/db"
)

// Start :
func Start(logToFile bool, logDir string, driver db.DB) error {
	e := echo.New()
	e.Debug = viper.GetBool("debug")

	// Middleware
	e.Use(middleware.RequestLoggerWithConfig(newRequestLoggerConfig(os.Stderr)))
	e.Use(middleware.Recover())

	// setup access logger
	if logToFile {
		logPath := filepath.Join(logDir, "access.log")
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return xerrors.Errorf("Failed to open a log file: %s", err)
		}
		defer f.Close()
		e.Use(middleware.RequestLoggerWithConfig(newRequestLoggerConfig(f)))
	}

	// Routes
	e.GET("/health", health())
	e.GET("/cves/:cve", getVulnByCveID(driver))
	e.POST("/multi-cves", getVulnByMultiCveID(driver))

	bindURL := fmt.Sprintf("%s:%s", viper.GetString("bind"), viper.GetString("port"))
	log15.Info("Listening...", "URL", bindURL)

	return e.Start(bindURL)
}

func newRequestLoggerConfig(writer io.Writer) middleware.RequestLoggerConfig {
	return middleware.RequestLoggerConfig{
		LogLatency:       true,
		LogRemoteIP:      true,
		LogHost:          true,
		LogMethod:        true,
		LogURI:           true,
		LogRequestID:     true,
		LogUserAgent:     true,
		LogStatus:        true,
		LogError:         true,
		LogContentLength: true,
		LogResponseSize:  true,

		LogValuesFunc: func(_ echo.Context, v middleware.RequestLoggerValues) error {
			type logFormat struct {
				Time         string `json:"time"`
				RemoteIP     string `json:"remote_ip"`
				Host         string `json:"host"`
				Method       string `json:"method"`
				URI          string `json:"uri"`
				ID           string `json:"id"`
				UserAgent    string `json:"user_agent"`
				Status       int    `json:"status"`
				Error        string `json:"error"`
				Latency      int64  `json:"latency"`
				LatencyHuman string `json:"latency_human"`
				BytesIn      int64  `json:"bytes_in"`
				BytesOut     int64  `json:"bytes_out"`
			}

			return json.NewEncoder(writer).Encode(logFormat{
				Time:      v.StartTime.Format(time.RFC3339Nano),
				RemoteIP:  v.RemoteIP,
				Host:      v.Host,
				Method:    v.Method,
				URI:       v.URI,
				ID:        v.RequestID,
				UserAgent: v.UserAgent,
				Status:    v.Status,
				Error: func() string {
					if v.Error != nil {
						return v.Error.Error()
					}
					return ""
				}(),
				Latency:      v.Latency.Nanoseconds(),
				LatencyHuman: v.Latency.String(),
				BytesIn: func() int64 {
					i, _ := strconv.ParseInt(v.ContentLength, 10, 64)
					return i
				}(),
				BytesOut: v.ResponseSize,
			})
		},
	}
}

func health() echo.HandlerFunc {
	return func(context echo.Context) error {
		return context.String(http.StatusOK, "")
	}
}

func getVulnByCveID(driver db.DB) echo.HandlerFunc {
	return func(context echo.Context) (err error) {
		cve := context.Param("cve")
		log15.Debug("Params", "CVE", cve)

		r, err := driver.GetKEVByCveID(cve)
		if err != nil {
			return xerrors.Errorf("Failed to get KEV Info by CVE. err: %w", err)
		}
		return context.JSON(http.StatusOK, r)
	}
}

type param struct {
	Args []string `json:"args"`
}

func getVulnByMultiCveID(driver db.DB) echo.HandlerFunc {
	return func(context echo.Context) (err error) {
		cveIDs := param{}
		if err := context.Bind(&cveIDs); err != nil {
			return err
		}
		log15.Debug("Params", "CVEIDs", cveIDs.Args)

		r, err := driver.GetKEVByMultiCveID(cveIDs.Args)
		if err != nil {
			return xerrors.Errorf("Failed to get KEV Info by CVE. err: %w", err)
		}
		return context.JSON(http.StatusOK, r)
	}
}
