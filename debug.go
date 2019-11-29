package ssloff

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type debugServer struct {
	mu               sync.Mutex
	peer             atomic.Value // *peerState
	lastPeer         *peerState
	lastMetric       peerMetric
	peerBytesRead    lineData
	peerBytesWritten lineData
	leafMap          map[string]*leafData
}

type lineData struct {
	buf []int64
	idx int
}

type leafData struct {
	bytesRead    lineData
	bytesWritten lineData
	skip         int
}

var globalDbgServer = debugServer{leafMap: map[string]*leafData{}}

func init() {
	globalDbgServer.peer.Store((*peerState)(nil))
}

const kMetricRingBufSize = 3600

func (ld *lineData) add(val int64) {
	if ld.buf == nil {
		ld.buf = make([]int64, kMetricRingBufSize)
	}
	ld.buf[ld.idx] = val
	ld.idx++
	ld.idx %= kMetricRingBufSize
}

func (ld *lineData) tail(n int) []int64 {
	dst := make([]int64, n)
	if ld.buf == nil {
		return dst
	}

	if n > kMetricRingBufSize {
		n = kMetricRingBufSize
	}

	if n < ld.idx {
		copy(dst, ld.buf[ld.idx-n:ld.idx])
	} else {
		copy(dst[n-ld.idx:], ld.buf[:ld.idx])
		copy(dst, ld.buf[kMetricRingBufSize-(n-ld.idx):])
	}
	return dst
}

func getInt(m map[string]string, key string, d int) int {
	if r, err := strconv.Atoi(m[key]); err == nil {
		return r
	}
	return d
}

func getStr(m map[string]string, key string, d string) string {
	if r, ok := m[key]; ok {
		return r
	}
	return d
}

var kUnits = []string{
	" B",
	"KB",
	"MB",
	"GB",
	"TB",
	"PB",
	"EB",
}

func makeYTicks(max int64) (ticks []int64, labels []string) {
	f := float64(max)
	mag := int64(1)
	for f >= 17 {
		f /= 10
		mag *= 10
	}
	nticks := int64(f) + 1

	n := mag
	ui := 0
	for n >= 1000 {
		n /= 1000
		ui++
	}

	unit := "??"
	if ui < len(kUnits) {
		unit = kUnits[ui]
	}

	for i := int64(1); i <= nticks; i++ {
		ticks = append(ticks, i*mag)
		labels = append(labels, fmt.Sprintf("%d%s", i*n, unit))
	}
	return
}

func makeSVGString(sp *svgParam, data []int64) string {
	sb := strings.Builder{}
	makeSVG(sp, data, &sb)
	return sb.String()
}

type svgParam struct {
	w      int
	h      int
	fill   string
	barw   int
	labelw int
	nbar   int
}

func makeSVGParam(param map[string]string) (sp *svgParam) {
	sp = &svgParam{}
	sp.w = getInt(param, "width", 600)
	sp.h = getInt(param, "height", 300)
	sp.fill = getStr(param, "color", "green")
	sp.barw = 4
	sp.labelw = 30
	sp.nbar = (sp.w - sp.labelw) / sp.barw
	return
}

func makeSVG(sp *svgParam, data []int64, writer io.Writer) {
	fmt.Fprintf(writer, `
<svg version="1.1" width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">
	<!-- border -->
    <rect x="0" y="0" width="%d" height="%d" stroke="grey" stroke-width="1" fill="none"/>`,
		sp.w, sp.h, sp.w, sp.h,
	)

	// bar data
	maxVal := int64(1000)
	for i := 0; i < sp.nbar; i++ {
		if data[i] > maxVal {
			maxVal = data[i]
		}
	}

	// y axes
	ticks, labels := makeYTicks(maxVal)

	// bars
	upperVal := ticks[len(ticks)-1]
	for i := 0; i < sp.nbar; i++ {
		val := data[sp.nbar-i-1]
		percent := float64(val) / float64(upperVal) * 100
		fmt.Fprintf(writer,
			`<rect x="%d" y="%f%%" width="%d" height="%f%%" fill="%s"/>`,
			(sp.nbar-i-1)*sp.barw, 100-percent, sp.barw, percent, html.EscapeString(sp.fill),
		)
	}

	// y axes
	for i, tval := range ticks {
		y := int((1 - float64(tval)/float64(upperVal)) * float64(sp.h))
		if y <= 0 {
			y = 1
		} else if y >= sp.h {
			y = sp.h - 1
		}

		fmt.Fprintf(writer, `<line x1="0" y1="%d" x2="%d" y2="%d" stroke="black" stroke-width="1" stroke-opacity="0.5"/>`,
			y, sp.w, y,
		)
		fmt.Fprintf(writer,
			`<text x="%d" y="%d" text-anchor="end" font-size="10px">%s</text>`,
			sp.w, y+10, labels[i],
		)
	}

	// TODO: x axes
	_, _ = writer.Write([]byte("</svg>\n"))
}

func dbgServerSetPeer(p *peerState) {
	globalDbgServer.peer.Store(p)
}

func collectMetric(s *debugServer) {
	p := s.peer.Load().(*peerState)
	if p == nil {
		return
	}

	curMetric := p.getMetric()
	if p != s.lastPeer {
		// compare with zero
		s.lastMetric = peerMetric{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// peer metric
	s.peerBytesRead.add(curMetric.BytesRead - s.lastMetric.BytesRead)
	s.peerBytesWritten.add(curMetric.BytesWritten - s.lastMetric.BytesWritten)

	// leaf metric
	for _, cur := range curMetric.Leaves {
		// dest
		if s.leafMap[cur.Leaf] == nil {
			s.leafMap[cur.Leaf] = &leafData{}
		}
		ld := s.leafMap[cur.Leaf]
		// last
		last := s.lastMetric.Leaves[cur.Leaf]
		if cur.Id != last.Id {
			// compare with zero
			last = leafMetric{}
		}
		// collect
		ld.bytesRead.add(cur.BytesRead - last.BytesRead)
		ld.bytesWritten.add(cur.BytesWritten - last.BytesWritten)
		ld.skip = 0
	}
	// clean up expired leaves
	for key, ld := range s.leafMap {
		if _, ok := curMetric.Leaves[key]; !ok {
			ld.bytesRead.add(0)
			ld.bytesWritten.add(0)
			ld.skip++
			if ld.skip >= kMetricRingBufSize {
				delete(s.leafMap, key)
			}
		}
	}

	s.lastPeer = p
	s.lastMetric = curMetric
}

func dbgServerStart() {
	go func() {
		for range time.Tick(1 * time.Second) {
			collectMetric(&globalDbgServer)
		}
	}()

	http.HandleFunc("/debug/ssloff/", dbgPage)
}

func dbgPage(w http.ResponseWriter, r *http.Request) {
	param := map[string]string{}
	_ = r.ParseForm()
	for k, vs := range r.Form {
		param[k] = vs[len(vs)-1]
	}

	sp := makeSVGParam(param)

	s := &globalDbgServer
	s.mu.Lock()
	peerRData := s.peerBytesRead.tail(sp.nbar)
	peerWData := s.peerBytesWritten.tail(sp.nbar)
	var leafLabels []string
	for key := range s.leafMap {
		leafLabels = append(leafLabels, key)
	}
	sort.Strings(leafLabels)
	var leafRData [][]int64
	var leafWData [][]int64
	for _, key := range leafLabels {
		leafRData = append(leafRData, s.leafMap[key].bytesRead.tail(sp.nbar))
		leafWData = append(leafWData, s.leafMap[key].bytesWritten.tail(sp.nbar))
	}
	s.mu.Unlock()

	refresh := getStr(param, "refresh", "0")
	doc := tag("html", attr{"lang", "en"},
		tag("head",
			tag("meta", attr{"charset", "UTF-8"}),
			cond(refresh != "0",
				tag("meta", attr{"http-equiv", "refresh", "content", refresh})),
			tag("title", "ssloff"),
			tag("style", `
				body {
					font-family: monospace;
				}
			`)),
		tag("body",
			tag("div",
				tag("div", attr{"id", "peer-bytes-read"},
					"peer_bytes_read:",
					tag("div", makeSVGString(sp, peerRData))),
				tag("div", attr{"id", "peer-bytes-written"},
					"peer_bytes_written:",
					tag("div", makeSVGString(sp, peerWData))),
				rangen(len(leafLabels)*2, func(i int) string {
					t := [2]string{" bytes_read:", " bytes_written:"}
					c := [2][][]int64{leafRData, leafWData}
					return tag("div",
						leafLabels[i/2], t[i%2],
						tag("div", makeSVGString(sp, c[i%2][i/2])))
				}),
			),
		))

	_, _ = w.Write([]byte(`<!DOCTYPE html>`))
	_, _ = w.Write([]byte(doc))
}
