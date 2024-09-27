// Package gcpmobilelog provides a [slog.Handler] that writes logs optimized for viewing on GCP Cloud Console Mobile.
package gcpmobilelog

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const errKey = "err"
const InfoKey = ">"
const ErrorKey = "ERROR"
const WarnKey = "WARN"
const DebugKey = "DBG"

var (
	defaultLevel      = slog.LevelInfo
	defaultTimeFormat = time.StampMilli
)

// Options for a slog.Handler that writes logs optimized for GCP Cloud Console, with options to improve Mobile viewing when structured JSON is not enabled.
//
// Use EnableJSON to use slog with github.com/mhpenta/logmon
type Options struct {
	// Enable source code location (Default: false)
	AddSource bool

	// Minimum level to log (Default: slog.LevelInfo)
	Level slog.Leveler

	// ReplaceAttr is called to rewrite each non-group attribute before it is logged.
	// See https://pkg.go.dev/log/slog#HandlerOptions for details.
	ReplaceAttr func(groups []string, attr slog.Attr) slog.Attr

	// TimeString format (Default: time.StampMilli)
	TimeFormat string

	// Disable color (Default: false)
	NoColor bool

	EnableJSON bool

	ProjectID string
}

// NewHandler creates a simple [slog.Handler] that writes GCP mobile optimized logs to Writer w,
// using the default options. If opts is nil, the default options are used.
func NewHandler(w io.Writer, opts *Options) slog.Handler {
	h := &handler{
		w:          w,
		level:      defaultLevel,
		timeFormat: defaultTimeFormat,
		enableJSON: opts.EnableJSON,
	}
	if opts == nil {
		return h
	}

	h.addSource = opts.AddSource
	if opts.Level != nil {
		h.level = opts.Level
	}
	h.replaceAttr = opts.ReplaceAttr
	if opts.TimeFormat != "" {
		h.timeFormat = opts.TimeFormat
	}
	h.noColor = opts.NoColor
	return h
}

// handler implements a [slog.Handler].
type handler struct {
	attrsPrefix string
	groupPrefix string
	groups      []string

	mu sync.Mutex
	w  io.Writer

	addSource   bool
	level       slog.Leveler
	replaceAttr func([]string, slog.Attr) slog.Attr
	timeFormat  string
	noColor     bool
	enableJSON  bool
	projectID   string
}

func (h *handler) clone() *handler {
	return &handler{
		attrsPrefix: h.attrsPrefix,
		groupPrefix: h.groupPrefix,
		groups:      h.groups,
		w:           h.w,
		addSource:   h.addSource,
		level:       h.level,
		replaceAttr: h.replaceAttr,
		timeFormat:  h.timeFormat,
		noColor:     h.noColor,
	}
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {

	if h.enableJSON {
		return h.handleJSON(ctx, r)
	}
	buf := newBuffer()
	defer buf.Free()

	rep := h.replaceAttr

	// write time
	if !r.Time.IsZero() {
		val := r.Time.Round(0) // strip monotonic to match Attr behavior
		if rep == nil {
			h.appendTime(buf, r.Time)
			buf.WriteByte(' ')
		} else if a := rep(nil, slog.Time(slog.TimeKey, val)); a.Key != "" {
			if a.Value.Kind() == slog.KindTime {
				h.appendTime(buf, a.Value.Time())
			} else {
				h.appendValue(buf, a.Value, false)
			}
			buf.WriteByte(' ')
		}
	}

	// write level
	if rep == nil {
		h.appendLevel(buf, r.Level)
		buf.WriteByte(' ')
	} else if a := rep(nil /* groups */, slog.Any(slog.LevelKey, r.Level)); a.Key != "" {
		h.appendValue(buf, a.Value, false)
		buf.WriteByte(' ')
	}

	// write source
	if h.addSource {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := fs.Next()
		if f.File != "" {
			src := &slog.Source{
				Function: f.Function,
				File:     f.File,
				Line:     f.Line,
			}

			if rep == nil {
				h.appendSource(buf, src)
				buf.WriteByte(' ')
			} else if a := rep(nil /* groups */, slog.Any(slog.SourceKey, src)); a.Key != "" {
				h.appendValue(buf, a.Value, false)
				buf.WriteByte(' ')
			}
		}
	}

	// write message
	if rep == nil {
		buf.WriteString(r.Message)
		buf.WriteByte(' ')
	} else if a := rep(nil /* groups */, slog.String(slog.MessageKey, r.Message)); a.Key != "" {
		h.appendValue(buf, a.Value, false)
		buf.WriteByte(' ')
	}

	// write handler attributes
	if len(h.attrsPrefix) > 0 {
		buf.WriteString(h.attrsPrefix)
	}

	// write attributes
	r.Attrs(func(attr slog.Attr) bool {
		h.appendAttr(buf, attr, h.groupPrefix, h.groups)
		return true
	})

	if len(*buf) == 0 {
		return nil
	}
	(*buf)[len(*buf)-1] = '\n' // replace last space with newline

	h.mu.Lock()
	defer h.mu.Unlock()

	_, err := h.w.Write(*buf)
	return err
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	h2 := h.clone()

	buf := newBuffer()
	defer buf.Free()

	// write attributes to buffer
	for _, attr := range attrs {
		h.appendAttr(buf, attr, h.groupPrefix, h.groups)
	}
	h2.attrsPrefix = h.attrsPrefix + string(*buf)
	return h2
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := h.clone()
	h2.groupPrefix += name + "."
	h2.groups = append(h2.groups, name)
	return h2
}

func (h *handler) appendTime(buf *buffer, t time.Time) {
	*buf = t.AppendFormat(*buf, h.timeFormat)
}

func (h *handler) appendLevel(buf *buffer, level slog.Level) {
	switch {
	case level < slog.LevelInfo:
		buf.WriteString(DebugKey)
		appendLevelDelta(buf, level-slog.LevelDebug)
	case level < slog.LevelWarn:
		buf.WriteString(InfoKey)
		appendLevelDelta(buf, level-slog.LevelInfo)
	case level < slog.LevelError:
		buf.WriteString(WarnKey)
		appendLevelDelta(buf, level-slog.LevelWarn)
	default:
		buf.WriteString(ErrorKey)
		appendLevelDelta(buf, level-slog.LevelError)
	}
}

func appendLevelDelta(buf *buffer, delta slog.Level) {
	if delta == 0 {
		return
	} else if delta > 0 {
		buf.WriteByte('+')
	}
	*buf = strconv.AppendInt(*buf, int64(delta), 10)
}

func (h *handler) appendSource(buf *buffer, src *slog.Source) {
	dir, file := filepath.Split(src.File)

	buf.WriteString(filepath.Join(filepath.Base(dir), file))
	buf.WriteByte(':')
	buf.WriteString(strconv.Itoa(src.Line))
}

func (h *handler) appendAttr(buf *buffer, attr slog.Attr, groupsPrefix string, groups []string) {
	attr.Value = attr.Value.Resolve()
	if rep := h.replaceAttr; rep != nil && attr.Value.Kind() != slog.KindGroup {
		attr = rep(groups, attr)
		attr.Value = attr.Value.Resolve()
	}

	if attr.Equal(slog.Attr{}) {
		return
	}

	if attr.Value.Kind() == slog.KindGroup {
		if attr.Key != "" {
			groupsPrefix += attr.Key + "."
			groups = append(groups, attr.Key)
		}
		for _, groupAttr := range attr.Value.Group() {
			h.appendAttr(buf, groupAttr, groupsPrefix, groups)
		}
	} else if err, ok := attr.Value.Any().(mobileLogError); ok {
		// append mobileLogError
		h.appendMobileLogError(buf, err, groupsPrefix)
		buf.WriteByte(' ')
	} else {
		h.appendKey(buf, attr.Key, groupsPrefix)
		h.appendValue(buf, attr.Value, true)
		buf.WriteByte(' ')
	}
}

func (h *handler) appendKey(buf *buffer, key, groups string) {
	appendString(buf, groups+key, true)
	buf.WriteByte('=')
}

func (h *handler) appendValue(buf *buffer, v slog.Value, quote bool) {
	switch v.Kind() {
	case slog.KindString:
		appendString(buf, v.String(), quote)
	case slog.KindInt64:
		*buf = strconv.AppendInt(*buf, v.Int64(), 10)
	case slog.KindUint64:
		*buf = strconv.AppendUint(*buf, v.Uint64(), 10)
	case slog.KindFloat64:
		*buf = strconv.AppendFloat(*buf, v.Float64(), 'g', -1, 64)
	case slog.KindBool:
		*buf = strconv.AppendBool(*buf, v.Bool())
	case slog.KindDuration:
		appendString(buf, v.Duration().String(), quote)
	case slog.KindTime:
		appendString(buf, v.Time().String(), quote)
	case slog.KindAny:
		switch cv := v.Any().(type) {
		case slog.Level:
			h.appendLevel(buf, cv)
		case encoding.TextMarshaler:
			data, err := cv.MarshalText()
			if err != nil {
				break
			}
			appendString(buf, string(data), quote)
		case *slog.Source:
			h.appendSource(buf, cv)
		default:
			appendString(buf, fmt.Sprint(v.Any()), quote)
		}
	}
}

func (h *handler) appendMobileLogError(buf *buffer, err error, groupsPrefix string) {

	appendString(buf, groupsPrefix+errKey, true)
	buf.WriteByte('=')
	appendString(buf, err.Error(), true)
}

func appendString(buf *buffer, s string, quote bool) {
	if quote && needsQuoting(s) {
		*buf = strconv.AppendQuote(*buf, s)
	} else {
		buf.WriteString(s)
	}
}

func needsQuoting(s string) bool {
	if len(s) == 0 {
		return true
	}
	for _, r := range s {
		if unicode.IsSpace(r) || r == '"' || r == '=' || !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

type mobileLogError struct{ error }

// Err returns a mobileLog [slog.Attr]
// When used with any other [slog.Handler], it behaves as
//
//	slog.Any("err", err)
func Err(err error) slog.Attr {
	if err != nil {
		err = mobileLogError{err}
	}
	return slog.Any(errKey, err)
}

func (h *handler) handleJSON(ctx context.Context, r slog.Record) error {
	data := make(map[string]interface{})

	// Add standard fields
	data["timestamp"] = r.Time.Format(time.RFC3339Nano)
	data["severity"] = h.levelToSeverity(r.Level)
	data["message"] = r.Message

	// Add source location if enabled
	if h.addSource {
		data["logging.googleapis.com/sourceLocation"] = h.getSourceLocation(r.PC)
	}

	// Add trace if available
	if trace := ctx.Value("trace"); trace != nil {
		data["logging.googleapis.com/trace"] = fmt.Sprintf("projects/%s/traces/%s", h.projectID, trace.(string))
	}

	// Add attributes
	r.Attrs(func(a slog.Attr) bool {
		key, value := h.attrToJSON(a)
		data[key] = value
		return true
	})

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err = h.w.Write(append(jsonData, '\n'))
	return err
}

func (h *handler) attrToJSON(attr slog.Attr) (string, interface{}) {
	key := attr.Key
	var value interface{}

	switch {
	case key == slog.MessageKey:
		key = "message"
		value = attr.Value.String()
	case key == slog.SourceKey:
		key = "logging.googleapis.com/sourceLocation"
		if src, ok := attr.Value.Any().(*slog.Source); ok {
			value = map[string]interface{}{
				"file":     src.File,
				"line":     src.Line,
				"function": src.Function,
			}
		}
	case key == slog.LevelKey:
		key = "severity"
		level := attr.Value.Any().(slog.Level)
		value = h.levelToSeverity(level)
	default:
		value = h.convertValue(attr.Value)
	}

	// If the key is part of a group, prefix it with the group name(s)
	if len(h.groups) > 0 {
		key = strings.Join(append(h.groups, key), ".")
	}

	return key, value
}

func (h *handler) convertValue(v slog.Value) interface{} {
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindBool:
		return v.Bool()
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().Format(time.RFC3339Nano)
	case slog.KindAny:
		return fmt.Sprint(v.Any())
	default:
		return v.String()
	}
}

func (h *handler) levelToSeverity(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "ERROR"
	case level >= slog.LevelWarn:
		return "WARNING"
	case level >= slog.LevelInfo:
		return "INFO"
	case level >= slog.LevelDebug:
		return "DEBUG"
	default:
		return "DEFAULT"
	}
}

func (h *handler) getSourceLocation(pc uintptr) map[string]interface{} {
	fs := runtime.CallersFrames([]uintptr{pc})
	f, _ := fs.Next()
	return map[string]interface{}{
		"file":     f.File,
		"line":     f.Line,
		"function": f.Function,
	}
}
