package ssloff

import (
	"html"
	"strings"
)

func cond(b bool, s string) string {
	if b {
		return s
	} else {
		return ""
	}
}

func rangen(n int, f func(int) string) string {
	var vs []string
	for i := 0; i < n; i++ {
		vs = append(vs, f(i))
	}
	return strings.Join(vs, "")
}

var kNoCloseTags = map[string]bool{
	"area":     true,
	"base":     true,
	"basefont": true,
	"br":       true,
	"col":      true,
	"frame":    true,
	"hr":       true,
	"img":      true,
	"input":    true,
	"isindex":  true,
	"link":     true,
	"meta":     true,
	"param":    true,
}

func tag(name string, aoc interface{}, children ...string) string {
	sb := strings.Builder{}

	sb.WriteString("<")
	sb.WriteString(name)
	if a, ok := aoc.(attr); ok {
		for i, kv := range a {
			if i%2 == 0 {
				sb.WriteString(" ")
				sb.WriteString(kv)
			} else {
				sb.WriteString(`="`)
				sb.WriteString(html.EscapeString(kv))
				sb.WriteString(`"`)
			}
		}
	}
	sb.WriteString(">")

	if s, ok := aoc.(string); ok {
		sb.WriteString(s)
	}
	for _, child := range children {
		sb.WriteString(child)
	}

	if !kNoCloseTags[name] {
		sb.WriteString("</")
		sb.WriteString(name)
		sb.WriteString(">")
	}
	return sb.String()
}

type attr []string
