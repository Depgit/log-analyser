package wireshark

// Magic bytes for pcap format detection.
const (
	// PcapMagicLE = little-endian pcap (most common)
	PcapMagicLE = "\xd4\xc3\xb2\xa1"
	// PcapMagicBE = big-endian pcap
	PcapMagicBE = "\xa1\xb2\xc3\xd4"
	// PcapngMagic = pcapng section header
	PcapngMagic = "\x0a\x0d\x0d\x0a"
)

// Field represents a single protocol field parsed from Wireshark output.
type Field struct {
	Name      string  `json:"name"`
	ShowName  string  `json:"showname"`
	ShowValue string  `json:"show"`
	Value     string  `json:"value"`
	Children  []Field `json:"children,omitempty"`
}

// Layer is a protocol layer within a packet.
type Layer struct {
	Name   string  `json:"name"`
	Fields []Field `json:"fields"`
}

// Packet is a fully parsed Wireshark packet.
type Packet struct {
	FrameNum  int      `json:"frame_num"`
	TimeEpoch string   `json:"time_epoch"`
	TimeDelta string   `json:"time_delta"`
	TimeRel   string   `json:"time_rel"`
	Src       string   `json:"src"`
	Dst       string   `json:"dst"`
	Protocol  string   `json:"protocol"`  // highest-level protocol detected
	Protocols []string `json:"protocols"` // all protocols from frame.protocols
	Length    int      `json:"length"`
	Info      string   `json:"info"`

	// Raw layers indexed by protocol name
	Layers map[string]Layer `json:"layers"`

	// Decoded protocol data (populated by dissectors)
	TCAP   *TCAPInfo   `json:"tcap,omitempty"`
	GSMMAP *GSMMAPInfo `json:"gsm_map,omitempty"`
	CAP    *CAPInfo    `json:"cap,omitempty"`
}

// TCAPInfo holds decoded TCAP layer information.
type TCAPInfo struct {
	MessageType string          `json:"message_type"` // Begin / Continue / End / Abort
	OTID        string          `json:"otid"`
	DTID        string          `json:"dtid"`
	AppContext  string          `json:"app_context"`
	Components  []TCAPComponent `json:"components,omitempty"`
}

// TCAPComponent represents a TCAP component (Invoke, ReturnResult, ReturnError, Reject).
type TCAPComponent struct {
	Type     string `json:"type"` // Invoke / ReturnResult / ReturnError / Reject
	InvokeID string `json:"invoke_id"`
	OpCode   string `json:"op_code"`
}

// GSMMAPInfo holds decoded GSM_MAP layer information.
type GSMMAPInfo struct {
	OpCode     string `json:"op_code"`
	OpName     string `json:"op_name"`
	InvokeID   string `json:"invoke_id"`
	AppContext string `json:"app_context"`
	IMSI       string `json:"imsi,omitempty"`
	MSISDN     string `json:"msisdn,omitempty"`
	CalledGT   string `json:"called_gt,omitempty"`
	CallingGT  string `json:"calling_gt,omitempty"`
	Component  string `json:"component"` // Invoke / ReturnResult / ReturnError / Reject
	ErrorCode  string `json:"error_code,omitempty"`
}

// CAPInfo holds decoded CAMEL Application Part (SCP/CAP) information.
type CAPInfo struct {
	Operation  string `json:"operation"` // e.g., InitialDP, Connect, ApplyCharging …
	ServiceKey string `json:"service_key,omitempty"`
	IMSI       string `json:"imsi,omitempty"`
	CalledNum  string `json:"called_number,omitempty"`
	CallingNum string `json:"calling_number,omitempty"`
	EventType  string `json:"event_type,omitempty"`
}
