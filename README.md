## gcpslogger

GCP Slogger is a simply logger for GCP Cloud Logging. When EnableJSON is false, the output is easily viewed on GCP Cloud mobile application. 

When EnableJSON is true, the output is in JSON format, which can be used for further processing, such as in mhpenta/logmon.

## Usage

```go

import (
    "log/slog"
    "github.com/mhpenta/gcpslogger"
)


func setupLogger() {
    gcpsloggerOptions := &gcpmobilelog.Options{
			Level:      slog.LevelInfo,
			TimeFormat: time.TimeOnly,
			EnableJSON: true,
	}
	gcpslogger := slog.New(gcpmobilelog.NewHandler(os.Stdout, gcpsloggerOptions))
	slog.SetDefault(gcpslogger)
}

```
