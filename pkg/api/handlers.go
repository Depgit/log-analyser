package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log-analyser/pkg/protocols"
	"log-analyser/pkg/wireshark"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ─── Session store ────────────────────────────────────────────────────────────

type session struct {
	Packets []wireshark.Packet `json:"packets"`
}

var (
	mu       sync.RWMutex
	sessions = make(map[string]*session)
	lastKey  = "default"
)

// ─── Router ───────────────────────────────────────────────────────────────────

func NewRouter(staticDir string) http.Handler {
	mux := http.NewServeMux()

	// Static frontend
	fs := http.FileServer(http.Dir(staticDir))
	mux.Handle("/", fs)

	// API
	mux.HandleFunc("/api/upload", handleUpload)
	mux.HandleFunc("/api/packets", handlePackets)
	mux.HandleFunc("/api/packet/", handlePacketDetail)
	mux.HandleFunc("/api/stats", handleStats)
	mux.HandleFunc("/api/flows", handleFlows)
	mux.HandleFunc("/api/search", handleSearch)
	mux.HandleFunc("/api/unanswered", handleUnanswered)

	return withCORS(mux)
}

// ─── Upload handler ───────────────────────────────────────────────────────────

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 512<<20) // 512 MB
	file, header, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "Failed to read upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Buffer entire upload so we can inspect magic bytes and retry parsers.
	data, err := io.ReadAll(file)
	if err != nil {
		jsonError(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))
	var packets []wireshark.Packet
	format := "unknown"

	// ── Step 1: detect pcap/pcapng by magic bytes (highest priority) ──────
	if wireshark.IsPcap(data) || ext == ".pcap" || ext == ".pcapng" || ext == ".cap" {
		format = "pcap"
		packets, err = wireshark.ParsePcapViaTshark(data)
		if err != nil {
			// Give the user a clear message with install instructions
			jsonError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	} else {
		// ── Step 2: PDML / JSON ─────────────────────────────────────────────
		switch ext {
		case ".pdml", ".xml":
			format = "pdml"
			packets, err = wireshark.ParsePDML(strings.NewReader(string(data)))
		case ".json":
			format = "json"
			packets, err = wireshark.ParseJSON(strings.NewReader(string(data)))
		default:
			// Sniff: try JSON then PDML
			packets, err = wireshark.ParseJSON(strings.NewReader(string(data)))
			if err == nil && len(packets) > 0 {
				format = "json"
			} else {
				packets, err = wireshark.ParsePDML(strings.NewReader(string(data)))
				if err == nil {
					format = "pdml"
				}
			}
		}
		if err != nil {
			jsonError(w, "Parse error: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	// Run dissectors on every packet
	for i := range packets {
		protocols.DissectTCAP(&packets[i])
		protocols.DissectGSMMAP(&packets[i])
		protocols.DissectCAP(&packets[i])
	}

	// Store session
	key := header.Filename
	mu.Lock()
	sessions[key] = &session{Packets: packets}
	lastKey = key
	mu.Unlock()

	writeJSON(w, map[string]interface{}{
		"session_key":      key,
		"packet_count":     len(packets),
		"filename":         header.Filename,
		"format":           format,
		"tshark_available": wireshark.FindTshark() != "",
	})
}

// ─── Packets list ─────────────────────────────────────────────────────────────

func handlePackets(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess == nil {
		jsonError(w, "No session – upload a file first", http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	proto := strings.ToLower(q.Get("proto"))   // filter by protocol
	search := strings.ToLower(q.Get("search")) // full-text search
	limitStr := q.Get("limit")
	offsetStr := q.Get("offset")

	limit := 500
	offset := 0
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil {
			limit = n
		}
	}
	if offsetStr != "" {
		if n, err := strconv.Atoi(offsetStr); err == nil {
			offset = n
		}
	}

	result := make([]wireshark.Packet, 0)
	for _, pkt := range sess.Packets {
		if proto != "" {
			match := false
			for _, p := range pkt.Protocols {
				if strings.EqualFold(p, proto) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		if search != "" && !packetContains(pkt, search) {
			continue
		}
		result = append(result, pkt)
	}

	total := len(result)
	if offset >= total {
		result = nil
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		result = result[offset:end]
	}

	type summary struct {
		FrameNum  int      `json:"frame_num"`
		TimeRel   string   `json:"time_rel"`
		TimeEpoch string   `json:"time_epoch"`
		Src       string   `json:"src"`
		Dst       string   `json:"dst"`
		Protocol  string   `json:"protocol"`
		Protocols []string `json:"protocols,omitempty"`
		Length    int      `json:"length"`
		Info      string   `json:"info"`
		TCAPType  string   `json:"tcap_type,omitempty"`
		MapOp     string   `json:"map_op,omitempty"`
		CAPOp     string   `json:"cap_op,omitempty"`
	}
	summaries := make([]summary, 0, len(result))
	for _, pkt := range result {
		s := summary{
			FrameNum:  pkt.FrameNum,
			TimeRel:   pkt.TimeRel,
			TimeEpoch: pkt.TimeEpoch,
			Src:       pkt.Src,
			Dst:       pkt.Dst,
			Protocol:  pkt.Protocol,
			Protocols: pkt.Protocols,
			Length:    pkt.Length,
			Info:      buildInfo(pkt),
		}
		if pkt.TCAP != nil {
			s.TCAPType = pkt.TCAP.MessageType
		}
		if pkt.GSMMAP != nil {
			s.MapOp = pkt.GSMMAP.OpName
			if s.MapOp == "" {
				s.MapOp = pkt.GSMMAP.OpCode
			}
		}
		if pkt.CAP != nil {
			s.CAPOp = pkt.CAP.Operation
		}
		summaries = append(summaries, s)
	}

	writeJSON(w, map[string]interface{}{
		"total":   total,
		"offset":  offset,
		"limit":   limit,
		"packets": summaries,
	})
}

// ─── Packet detail ────────────────────────────────────────────────────────────

func handlePacketDetail(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess == nil {
		jsonError(w, "No session", http.StatusNotFound)
		return
	}

	// Extract frame number from URL: /api/packet/42
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		jsonError(w, "Missing frame number", http.StatusBadRequest)
		return
	}
	num, err := strconv.Atoi(parts[3])
	if err != nil {
		jsonError(w, "Invalid frame number", http.StatusBadRequest)
		return
	}

	for _, pkt := range sess.Packets {
		if pkt.FrameNum == num {
			writeJSON(w, pkt)
			return
		}
	}
	jsonError(w, fmt.Sprintf("Packet %d not found", num), http.StatusNotFound)
}

// ─── Statistics ───────────────────────────────────────────────────────────────

func handleStats(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess == nil {
		jsonError(w, "No session", http.StatusNotFound)
		return
	}

	protoDist := make(map[string]int)
	allProtosDist := make(map[string]int)
	mapOps := make(map[string]int)
	capOps := make(map[string]int)
	tcapTypes := make(map[string]int)

	for _, pkt := range sess.Packets {
		protoDist[pkt.Protocol]++
		for _, p := range pkt.Protocols {
			allProtosDist[p]++
		}
		if pkt.TCAP != nil && pkt.TCAP.MessageType != "" {
			tcapTypes[pkt.TCAP.MessageType]++
		}
		if pkt.GSMMAP != nil && pkt.GSMMAP.OpName != "" {
			mapOps[pkt.GSMMAP.OpName]++
		}
		if pkt.CAP != nil && pkt.CAP.Operation != "" {
			capOps[pkt.CAP.Operation]++
		}
	}

	writeJSON(w, map[string]interface{}{
		"total_packets":      len(sess.Packets),
		"protocol_dist":      protoDist,
		"all_protocols_dist": allProtosDist,
		"tcap_message_types": tcapTypes,
		"gsm_map_operations": mapOps,
		"cap_operations":     capOps,
	})
}

// ─── TCAP Transaction flows ───────────────────────────────────────────────────

type Flow struct {
	OTID     string        `json:"otid"`
	DTID     string        `json:"dtid,omitempty"`
	Messages []FlowMessage `json:"messages"`
}

type FlowMessage struct {
	FrameNum int    `json:"frame_num"`
	TimeRel  string `json:"time_rel"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	TCAPType string `json:"tcap_type"`
	MAPOp    string `json:"map_op,omitempty"`
	CAPOp    string `json:"cap_op,omitempty"`
}

func handleFlows(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess == nil {
		jsonError(w, "No session", http.StatusNotFound)
		return
	}

	flowMap := make(map[string]*Flow)
	for _, pkt := range sess.Packets {
		if pkt.TCAP == nil {
			continue
		}
		key := pkt.TCAP.OTID
		if key == "" {
			continue
		}
		if _, ok := flowMap[key]; !ok {
			flowMap[key] = &Flow{OTID: pkt.TCAP.OTID}
		}
		f := flowMap[key]
		if pkt.TCAP.DTID != "" {
			f.DTID = pkt.TCAP.DTID
		}
		msg := FlowMessage{
			FrameNum: pkt.FrameNum,
			TimeRel:  pkt.TimeRel,
			Src:      pkt.Src,
			Dst:      pkt.Dst,
			TCAPType: pkt.TCAP.MessageType,
		}
		if pkt.GSMMAP != nil {
			msg.MAPOp = pkt.GSMMAP.OpName
		}
		if pkt.CAP != nil {
			msg.CAPOp = pkt.CAP.Operation
		}
		f.Messages = append(f.Messages, msg)
	}

	flows := make([]*Flow, 0, len(flowMap))
	for _, v := range flowMap {
		flows = append(flows, v)
	}
	writeJSON(w, flows)
}

// ─── Search ───────────────────────────────────────────────────────────────────

func handleSearch(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess == nil {
		jsonError(w, "No session", http.StatusNotFound)
		return
	}
	q := strings.ToLower(r.URL.Query().Get("q"))
	if q == "" {
		jsonError(w, "Missing ?q= parameter", http.StatusBadRequest)
		return
	}

	type hit struct {
		FrameNum int    `json:"frame_num"`
		Protocol string `json:"protocol"`
		Src      string `json:"src"`
		Dst      string `json:"dst"`
		Info     string `json:"info"`
	}
	hits := []hit{}
	for _, pkt := range sess.Packets {
		if packetContains(pkt, q) {
			hits = append(hits, hit{
				FrameNum: pkt.FrameNum,
				Protocol: pkt.Protocol,
				Src:      pkt.Src,
				Dst:      pkt.Dst,
				Info:     buildInfo(pkt),
			})
		}
	}
	writeJSON(w, hits)
}

// ─── Unanswered Request Detection ───────────────────────────────────────────────

type UnansweredRequest struct {
	FrameNum      int    `json:"frame_num"`
	TimeRel       string `json:"time_rel"`
	Src           string `json:"src"`
	Dst           string `json:"dst"`
	IMSI          string `json:"imsi,omitempty"`
	MSISDN        string `json:"msisdn,omitempty"`
	Operation     string `json:"operation"`
	InvokeID      string `json:"invoke_id"`
	Status        string `json:"status"` // "no_response" or "error_response"
	ErrorCode     string `json:"error_code,omitempty"`
	ResponseFrame int    `json:"response_frame,omitempty"` // Frame number of error response
	OTID          string `json:"-"`
}

func handleUnanswered(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess == nil {
		jsonError(w, "No session", http.StatusNotFound)
		return
	}

	pending := make(map[string]*UnansweredRequest)
	errorResponses := make(map[string]*UnansweredRequest)
	dialogIMSI := make(map[string]string)
	dialogMSISDN := make(map[string]string)

	for _, pkt := range sess.Packets {
		if pkt.TCAP == nil {
			continue
		}

		// Extract IMSI/MSISDN to enrich the dialog
		imsi, msisdn, opName := "", "", ""
		if pkt.GSMMAP != nil {
			imsi = pkt.GSMMAP.IMSI
			msisdn = pkt.GSMMAP.MSISDN
			opName = pkt.GSMMAP.OpName
			if opName == "" {
				opName = pkt.GSMMAP.OpCode
			}
		} else if pkt.CAP != nil {
			imsi = pkt.CAP.IMSI
			opName = pkt.CAP.Operation
		}

		if imsi != "" {
			if pkt.TCAP.OTID != "" {
				dialogIMSI[pkt.TCAP.OTID] = imsi
			}
			if pkt.TCAP.DTID != "" {
				dialogIMSI[pkt.TCAP.DTID] = imsi
			}
		}
		if msisdn != "" {
			if pkt.TCAP.OTID != "" {
				dialogMSISDN[pkt.TCAP.OTID] = msisdn
			}
			if pkt.TCAP.DTID != "" {
				dialogMSISDN[pkt.TCAP.DTID] = msisdn
			}
		}

		for _, comp := range pkt.TCAP.Components {
			ct := strings.ToLower(comp.Type)
			if strings.Contains(ct, "invoke") {
				key := pkt.TCAP.OTID + ":" + comp.InvokeID
				pending[key] = &UnansweredRequest{
					FrameNum:  pkt.FrameNum,
					TimeRel:   pkt.TimeRel,
					Src:       pkt.Src,
					Dst:       pkt.Dst,
					IMSI:      imsi,
					MSISDN:    msisdn,
					Operation: opName,
					InvokeID:  comp.InvokeID,
					Status:    "no_response",
					OTID:      pkt.TCAP.OTID,
				}
			} else if strings.Contains(ct, "return") && !strings.Contains(ct, "error") {
				// Normal return result - remove from pending
				if pkt.TCAP.OTID != "" {
					delete(pending, pkt.TCAP.OTID+":"+comp.InvokeID)
				}
				if pkt.TCAP.DTID != "" {
					delete(pending, pkt.TCAP.DTID+":"+comp.InvokeID)
				}
			} else if strings.Contains(ct, "error") || strings.Contains(ct, "reject") {
				// Error response - mark as error_response
				errorKey := ""
				var origReq *UnansweredRequest

				// Try OTID first
				if pkt.TCAP.OTID != "" {
					key := pkt.TCAP.OTID + ":" + comp.InvokeID
					if req, exists := pending[key]; exists {
						origReq = req
						errorKey = key
					}
				}
				// Try DTID if OTID didn't match
				if origReq == nil && pkt.TCAP.DTID != "" {
					key := pkt.TCAP.DTID + ":" + comp.InvokeID
					if req, exists := pending[key]; exists {
						origReq = req
						errorKey = key
					}
				}

				if origReq != nil {
					// Mark as error response
					origReq.Status = "error_response"
					origReq.ErrorCode = comp.OpCode
					origReq.ResponseFrame = pkt.FrameNum
					// Store in error responses and remove from pending
					errorResponses[errorKey] = origReq
					delete(pending, errorKey)
				}
			}
		}
	}

	// Combine pending (no_response) and error responses
	results := make([]*UnansweredRequest, 0, len(pending)+len(errorResponses))

	// Add no_response items
	for _, req := range pending {
		// Enrich with dialog IMSI/MSISDN if missing
		if req.IMSI == "" {
			req.IMSI = dialogIMSI[req.OTID]
		}
		if req.MSISDN == "" {
			req.MSISDN = dialogMSISDN[req.OTID]
		}
		results = append(results, req)
	}

	// Add error_response items
	for _, req := range errorResponses {
		// Enrich with dialog IMSI/MSISDN if missing
		if req.IMSI == "" {
			req.IMSI = dialogIMSI[req.OTID]
		}
		if req.MSISDN == "" {
			req.MSISDN = dialogMSISDN[req.OTID]
		}
		results = append(results, req)
	}

	writeJSON(w, results)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func getSession(r *http.Request) *session {
	key := r.URL.Query().Get("session")
	mu.RLock()
	defer mu.RUnlock()
	if key == "" {
		return sessions[lastKey]
	}
	return sessions[key]
}

func packetContains(pkt wireshark.Packet, q string) bool {
	fields := []string{pkt.Src, pkt.Dst, pkt.Protocol, pkt.Info}
	if pkt.GSMMAP != nil {
		fields = append(fields, pkt.GSMMAP.OpName, pkt.GSMMAP.IMSI, pkt.GSMMAP.MSISDN)
	}
	if pkt.TCAP != nil {
		fields = append(fields, pkt.TCAP.MessageType, pkt.TCAP.OTID, pkt.TCAP.DTID)
	}
	if pkt.CAP != nil {
		fields = append(fields, pkt.CAP.Operation, pkt.CAP.IMSI, pkt.CAP.CalledNum)
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func buildInfo(pkt wireshark.Packet) string {
	parts := []string{}
	if pkt.TCAP != nil && pkt.TCAP.MessageType != "" {
		parts = append(parts, "TCAP:"+pkt.TCAP.MessageType)
	}
	if pkt.GSMMAP != nil && pkt.GSMMAP.OpName != "" {
		parts = append(parts, "MAP:"+pkt.GSMMAP.OpName)
	}
	if pkt.CAP != nil && pkt.CAP.Operation != "" {
		parts = append(parts, "CAP:"+pkt.CAP.Operation)
	}
	if len(parts) > 0 {
		return strings.Join(parts, " | ")
	}

	// Fallback to M3UA message type
	if layer, ok := pkt.Layers["m3ua"]; ok {
		if info := wireshark.FieldShowName(layer, "m3ua.message_type"); info != "" {
			return info
		}
	}
	// Fallback to SCCP message type
	if layer, ok := pkt.Layers["sccp"]; ok {
		if info := wireshark.FieldShowName(layer, "sccp.message_type"); info != "" {
			return info
		}
	}
	// Fallback to SCTP chunk type
	if layer, ok := pkt.Layers["sctp"]; ok {
		if info := wireshark.FieldShowName(layer, "sctp.chunk_type"); info != "" {
			return info
		}
	}

	if pkt.Protocol != "" && pkt.Protocol != "unknown" {
		return strings.ToUpper(pkt.Protocol)
	}

	return pkt.Info
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
