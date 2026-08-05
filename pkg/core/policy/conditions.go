package policy

import (
	"net"
	"strings"
	"time"
)

// MatchCondition reports whether the request context satisfies a policy's
// when-clause. A nil condition always matches. Conditions are matching
// clauses, not requirements: a non-matching condition makes the policy fall
// through to the next one.
func MatchCondition(c *Condition, req *PolicyRequest) bool {
	if c == nil {
		return true
	}
	if len(c.IPCIDR) > 0 && !matchIPCIDR(c.IPCIDR, req.ClientIP) {
		return false
	}
	if c.TimeWindow != nil && !matchTimeWindow(c.TimeWindow, evalTime(req)) {
		return false
	}
	for name, want := range c.Headers {
		if req.Headers == nil || !strings.EqualFold(headerValue(req.Headers, name), want) {
			return false
		}
	}
	return true
}

func evalTime(req *PolicyRequest) time.Time {
	if !req.Now.IsZero() {
		return req.Now
	}
	return time.Now()
}

// matchIPCIDR reports whether ip falls inside any entry (CIDR or bare IP).
func matchIPCIDR(entries []string, clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false // unparseable client IP never matches an IP condition
	}
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if other := net.ParseIP(entry); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}

// matchTimeWindow reports whether t falls inside the daily window.
func matchTimeWindow(w *TimeWindow, t time.Time) bool {
	loc := time.UTC
	if w.TZ != "" {
		if l, err := time.LoadLocation(w.TZ); err == nil {
			loc = l
		} else {
			return false // unknown zone fails closed
		}
	}
	local := t.In(loc)

	if len(w.Days) > 0 && !containsString(normalizeDays(w.Days), strings.ToLower(local.Weekday().String()[:3])) {
		return false
	}

	start, err1 := time.Parse("15:04", w.Start)
	end, err2 := time.Parse("15:04", w.End)
	if err1 != nil || err2 != nil {
		return false // malformed window fails closed
	}
	minutes := local.Hour()*60 + local.Minute()
	startMin := start.Hour()*60 + start.Minute()
	endMin := end.Hour()*60 + end.Minute()

	if startMin <= endMin {
		return minutes >= startMin && minutes < endMin
	}
	// Overnight window, e.g. 22:00–06:00.
	return minutes >= startMin || minutes < endMin
}

func normalizeDays(days []string) []string {
	out := make([]string, 0, len(days))
	for _, d := range days {
		d = strings.ToLower(strings.TrimSpace(d))
		if len(d) >= 3 {
			out = append(out, d[:3])
		}
	}
	return out
}

// headerValue does a case-insensitive header name lookup.
func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}
