package broker

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"sync"
)

// Usage is what one forwarded call used, as its response reported it: the
// token counts, never the content.
type Usage struct {
	Model string
	// InputTokens excludes the cached tokens, which are counted apart, as
	// Anthropic reports them (OpenAI's prompt count includes them; they are
	// taken out).
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	// Status is the response's HTTP status (502 when the upstream failed).
	Status int
	// Truncated: a successful response ended without its final usage
	// report: a stream cut short, or a Chat Completions stream whose client
	// did not ask for usage. The counts are what was seen.
	Truncated bool
}

// UsageFormat says how a channel's responses report usage.
type UsageFormat int

const (
	// UsageNone: usage is not read.
	UsageNone UsageFormat = iota
	// UsageAnthropic: the Messages API. A JSON response's usage, or a
	// stream's message_start and message_delta events.
	UsageAnthropic
	// UsageOpenAI: the Chat Completions and Responses APIs. A JSON
	// response's usage, or a stream's last chunk with usage (Chat
	// Completions, with stream_options.include_usage) or its
	// response.completed event (Responses).
	UsageOpenAI
)

const (
	// maxUsageJSON caps how much of a JSON response is kept to find its
	// usage; past it the counts are reported as truncated.
	maxUsageJSON = 8 << 20
	// maxUsageLine caps one stream line; longer ones (large content
	// deltas) are skipped, since usage arrives on short ones.
	maxUsageLine = 1 << 20
)

// usageBody passes a response through unchanged, reading its usage on the
// way, and reports it once: at the end of the body, or when it is closed
// early.
type usageBody struct {
	io.ReadCloser
	format UsageFormat
	report func(Usage)
	once   sync.Once

	u      Usage
	final  bool // the response's final usage report was seen
	stream bool
	buf    bytes.Buffer // JSON: the body; stream: the current partial line
	over   bool         // JSON past maxUsageJSON, or a stream line past maxUsageLine
}

func newUsageBody(body io.ReadCloser, status int, contentType string, format UsageFormat, report func(Usage)) *usageBody {
	mt, _, _ := mime.ParseMediaType(contentType)
	return &usageBody{ReadCloser: body, format: format, report: report, u: Usage{Status: status}, stream: mt == "text/event-stream"}
}

func (b *usageBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.feed(p[:n])
	if err != nil {
		b.done()
	}
	return n, err
}

func (b *usageBody) Close() error {
	err := b.ReadCloser.Close()
	b.done()
	return err
}

func (b *usageBody) feed(p []byte) {
	if !b.stream {
		if !b.over {
			if b.buf.Len()+len(p) > maxUsageJSON {
				b.over, b.buf = true, bytes.Buffer{}
			} else {
				b.buf.Write(p)
			}
		}
		return
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if b.buf.Len()+len(p) > maxUsageLine {
				b.over = true
				b.buf.Reset()
			} else if !b.over {
				b.buf.Write(p)
			}
			return
		}
		if !b.over && b.buf.Len()+i <= maxUsageLine {
			b.buf.Write(p[:i])
			b.line(b.buf.Bytes())
		}
		b.buf.Reset()
		b.over = false
		p = p[i+1:]
	}
}

// line reads one stream line: its data, if it is a data line.
func (b *usageBody) line(l []byte) {
	l = bytes.TrimRight(l, "\r")
	data, ok := bytes.CutPrefix(l, []byte("data:"))
	if !ok {
		return
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return // "[DONE]", keep-alives
	}
	var ev streamEvent
	if json.Unmarshal(data, &ev) != nil {
		return
	}
	switch b.format {
	case UsageAnthropic:
		switch ev.Type {
		case "message_start":
			if ev.Message != nil {
				b.u.Model = ev.Message.Model
				b.add(ev.Message.Usage, false)
			}
		case "message_delta":
			// Counts here are cumulative for the message.
			b.add(ev.Usage, false)
			b.final = true
		}
	case UsageOpenAI:
		if ev.Type == "response.completed" && ev.Response != nil {
			b.u.Model = ev.Response.Model
			b.add(ev.Response.Usage, true)
			b.final = true
		} else if ev.Usage != nil && ev.Type == "" {
			// A Chat Completions chunk: usage is on the last one only.
			b.u.Model = ev.Model
			b.add(ev.Usage, true)
			b.final = true
		}
	}
}

func (b *usageBody) done() {
	b.once.Do(func() {
		if !b.stream && !b.over && b.buf.Len() > 0 {
			var resp streamEvent
			if json.Unmarshal(b.buf.Bytes(), &resp) == nil && resp.Usage != nil {
				b.u.Model = resp.Model
				b.add(resp.Usage, b.format == UsageOpenAI)
				b.final = true
			}
		}
		b.buf = bytes.Buffer{}
		b.u.Truncated = !b.final && b.u.Status >= 200 && b.u.Status < 300
		b.report(b.u)
	})
}

// add takes a usage report's counts. Anthropic's fields are already apart;
// OpenAI's prompt count includes the cached tokens, which are taken out. A
// zero in a later (cumulative) report keeps the earlier count.
func (b *usageBody) add(u *usageCounts, openAI bool) {
	if u == nil {
		return
	}
	set := func(dst *int64, v int64) {
		if v > 0 {
			*dst = v
		}
	}
	if openAI {
		in, cached := u.InputTokens+u.PromptTokens, u.InputDetails.CachedTokens+u.PromptDetails.CachedTokens
		set(&b.u.InputTokens, in-cached)
		set(&b.u.CacheReadTokens, cached)
		set(&b.u.OutputTokens, u.OutputTokens+u.CompletionTokens)
		return
	}
	set(&b.u.InputTokens, u.InputTokens)
	set(&b.u.OutputTokens, u.OutputTokens)
	set(&b.u.CacheReadTokens, u.CacheReadInputTokens)
	set(&b.u.CacheWriteTokens, u.CacheCreationInputTokens)
}

// streamEvent is the part of a response, or of one stream event, that
// carries usage, for both providers.
type streamEvent struct {
	Type    string       `json:"type"`
	Model   string       `json:"model"`
	Usage   *usageCounts `json:"usage"`
	Message *struct {
		Model string       `json:"model"`
		Usage *usageCounts `json:"usage"`
	} `json:"message"` // Anthropic message_start
	Response *struct {
		Model string       `json:"model"`
		Usage *usageCounts `json:"usage"`
	} `json:"response"` // OpenAI response.completed
}

type usageCounts struct {
	// Anthropic, and OpenAI's Responses API.
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	// Anthropic.
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	// OpenAI's Chat Completions API.
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	PromptDetails    struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	InputDetails struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}
