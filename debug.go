package ssloff

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type debugServer struct {
	mu      sync.Mutex
	peerMap map[uintptr]*debugPeer
}

type debugPeer struct {
	mu               sync.Mutex
	peer             *peerState
	lastPeer         *peerState
	lastMetric       peerMetric
	peerBytesRead    lineData
	peerBytesWritten lineData
	leafMap          map[uint32]*leafData
}

type lineData struct {
	buf []int64
	idx int
}

type leafData struct {
	target       string
	from         string
	bytesRead    lineData
	bytesWritten lineData
	skip         int
}

var globalDbgServer = debugServer{peerMap: map[uintptr]*debugPeer{}}

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
	for f > 40 {
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
	factor := 1
	for len(ticks)/factor*15 >= sp.h {
		factor++
	}
	for i, tval := range ticks {
		if i%factor != factor-1 {
			continue // avoid overlapping ticks
		}

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

func dbgServerAddPeer(key uintptr, p *peerState) {
	globalDbgServer.mu.Lock()
	defer globalDbgServer.mu.Unlock()
	if _, ok := globalDbgServer.peerMap[key]; !ok {
		globalDbgServer.peerMap[key] = &debugPeer{leafMap: map[uint32]*leafData{}}
	}
	globalDbgServer.peerMap[key].mu.Lock()
	globalDbgServer.peerMap[key].peer = p
	globalDbgServer.peerMap[key].mu.Unlock()
}

func dbgServerDelPeer(key uintptr) {
	globalDbgServer.mu.Lock()
	defer globalDbgServer.mu.Unlock()
	delete(globalDbgServer.peerMap, key)
}

func collectMetric(dp *debugPeer) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	curMetric := dp.peer.getMetric()
	if dp.peer != dp.lastPeer {
		// reset metric
		dp.lastMetric = peerMetric{}
		dp.leafMap = map[uint32]*leafData{}
	}

	// peer metric
	dp.peerBytesRead.add(curMetric.BytesRead - dp.lastMetric.BytesRead)
	dp.peerBytesWritten.add(curMetric.BytesWritten - dp.lastMetric.BytesWritten)

	// leaf metric
	for _, cur := range curMetric.Leaves {
		// dest
		if dp.leafMap[cur.Id] == nil {
			dp.leafMap[cur.Id] = &leafData{target: cur.Target, from: cur.From}
		}
		ld := dp.leafMap[cur.Id]
		// last
		last := dp.lastMetric.Leaves[cur.Id]
		// collect
		ld.bytesRead.add(cur.BytesRead - last.BytesRead)
		ld.bytesWritten.add(cur.BytesWritten - last.BytesWritten)
		ld.skip = 0
	}
	// clean up expired leaves
	for key, ld := range dp.leafMap {
		if _, ok := curMetric.Leaves[key]; !ok {
			ld.bytesRead.add(0)
			ld.bytesWritten.add(0)
			ld.skip++
			if ld.skip >= kMetricRingBufSize {
				delete(dp.leafMap, key)
			}
		}
	}
	// TODO: limit dp.leafMap size

	dp.lastPeer = dp.peer
	dp.lastMetric = curMetric
}

func dbgServerStart() {
	go func() {
		for range time.Tick(1 * time.Second) {
			globalDbgServer.mu.Lock()
			dps := make([]*debugPeer, 0, len(globalDbgServer.peerMap))
			for _, dp := range globalDbgServer.peerMap {
				dps = append(dps, dp)
			}
			globalDbgServer.mu.Unlock()

			for _, dp := range dps {
				collectMetric(dp)
			}
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
	spRW := [2]svgParam{*sp, *sp}
	spRW[0].fill = "blue"
	spRW[1].fill = "green"

	var peerName []string
	var peerRData [][]int64
	var peerWData [][]int64
	var leafRData [][][]int64
	var leafWData [][][]int64
	var leafLabels [][]string

	s := &globalDbgServer
	s.mu.Lock()
	nPeer := len(s.peerMap)
	for _, dp := range s.peerMap {
		dp.mu.Lock()

		peerName = append(peerName, dp.peer.pmetric.Peer)
		peerRData = append(peerRData, dp.peerBytesRead.tail(sp.nbar))
		peerWData = append(peerWData, dp.peerBytesWritten.tail(sp.nbar))

		var iLeafIds []uint32
		var iLeafLabels []string
		for lid, ld := range dp.leafMap {
			iLeafIds = append(iLeafIds, lid)
			label := ld.from + " -> " + ld.target
			if ld.skip > 0 {
				label = "[dead] " + label
			}
			iLeafLabels = append(iLeafLabels, label)
		}
		var iLeafRData [][]int64
		var iLeafWData [][]int64
		for _, lid := range iLeafIds {
			iLeafRData = append(iLeafRData, dp.leafMap[lid].bytesRead.tail(sp.nbar))
			iLeafWData = append(iLeafWData, dp.leafMap[lid].bytesWritten.tail(sp.nbar))
		}
		// TODO: sort by leaf labels

		leafLabels = append(leafLabels, iLeafLabels)
		leafRData = append(leafRData, iLeafRData)
		leafWData = append(leafWData, iLeafWData)

		dp.mu.Unlock()
	}
	s.mu.Unlock()

	makeURL := func(key, val string) string {
		uv := url.Values{}
		for k, v := range param {
			uv.Set(k, v)
		}
		uv.Set(key, val)
		return "?" + uv.Encode()
	}

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
			tag("div", "refresh: ",
				tag("a", attr{"href", makeURL("refresh", "0")}, "NO"), " | ",
				tag("a", attr{"href", makeURL("refresh", "1")}, "1s"), " | ",
				tag("a", attr{"href", makeURL("refresh", "2")}, "2s"), " | ",
				tag("a", attr{"href", makeURL("refresh", "5")}, "5s"), " | ",
			),
			tag("div", "width: ",
				tag("a", attr{"href", makeURL("width", "200")}, "200"), " | ",
				tag("a", attr{"href", makeURL("width", "400")}, "400"), " | ",
				tag("a", attr{"href", makeURL("width", "800")}, "800"), " | ",
				tag("a", attr{"href", makeURL("width", "1200")}, "1200"), " | ",
			),
			tag("div", "height: ",
				tag("a", attr{"href", makeURL("height", "30")}, "30"), " | ",
				tag("a", attr{"href", makeURL("height", "60")}, "&nbsp;", "60"), " | ",
				tag("a", attr{"href", makeURL("height", "100")}, "100"), " | ",
				tag("a", attr{"href", makeURL("height", "200")}, "200"), " | ",
			),
			tag("br", nil),
			rangen(nPeer, func(pi int) string {
				return tag("div",
					"peer: ", peerName[pi], " nLeafs: ", fmt.Sprint(len(leafLabels[pi])),
					tag("div",
						"peer_bytes_read:",
						tag("div", makeSVGString(&spRW[0], peerRData[pi]))),
					tag("div",
						"peer_bytes_written:",
						tag("div", makeSVGString(&spRW[1], peerWData[pi]))),
					rangen(len(leafLabels[pi])*2, func(li int) string {
						t := [2]string{" bytes_read:", " bytes_written:"}
						c := [2][][]int64{leafRData[pi], leafWData[pi]}
						return tag("div",
							leafLabels[pi][li/2], t[li%2],
							tag("div", makeSVGString(&spRW[li%2], c[li%2][li/2])))
					}),
				)
			}),
		))

	_, _ = w.Write([]byte(`<!DOCTYPE html>`))
	_, _ = w.Write([]byte(doc))
}
