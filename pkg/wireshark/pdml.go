package wireshark

import (
	"encoding/xml"
	"io"
	"strconv"
	"strings"
)

// ---------- XML structures matching PDML schema ----------

type pdmlRoot struct {
	XMLName xml.Name     `xml:"pdml"`
	Packets []pdmlPacket `xml:"packet"`
}

type pdmlPacket struct {
	Protos []pdmlProto `xml:"proto"`
}

type pdmlProto struct {
	Name   string      `xml:"name,attr"`
	Fields []pdmlField `xml:"field"`
}

type pdmlField struct {
	Name     string      `xml:"name,attr"`
	ShowName string      `xml:"showname,attr"`
	Show     string      `xml:"show,attr"`
	Value    string      `xml:"value,attr"`
	Children []pdmlField `xml:"field"`
}

// ---------- Public API ----------

// ParsePDML reads a Wireshark PDML XML stream and returns a slice of Packets.
func ParsePDML(r io.Reader) ([]Packet, error) {
	var root pdmlRoot
	dec := xml.NewDecoder(r)
	dec.Strict = false
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}

	packets := make([]Packet, 0, len(root.Packets))
	for i, pp := range root.Packets {
		pkt := pdmlToPacket(i+1, pp)
		packets = append(packets, pkt)
	}
	return packets, nil
}

// ---------- Internal helpers ----------

func pdmlToPacket(idx int, pp pdmlPacket) Packet {
	pkt := Packet{
		FrameNum: idx,
		Layers:   make(map[string]Layer),
	}

	for _, proto := range pp.Protos {
		layer := Layer{Name: proto.Name}
		for _, f := range proto.Fields {
			layer.Fields = append(layer.Fields, convertField(f))
		}
		pkt.Layers[proto.Name] = layer

		switch proto.Name {
		case "frame":
			for _, f := range proto.Fields {
				switch f.Name {
				case "frame.number":
					if n, err := strconv.Atoi(f.Show); err == nil {
						pkt.FrameNum = n
					}
				case "frame.time_epoch":
					pkt.TimeEpoch = f.Show
				case "frame.time_relative":
					pkt.TimeRel = f.Show
				case "frame.time_delta":
					pkt.TimeDelta = f.Show
				case "frame.len":
					if n, err := strconv.Atoi(f.Show); err == nil {
						pkt.Length = n
					}
				case "frame.protocols":
					pkt.Info = f.Show
					if pkt.Info != "" {
						pkt.Protocols = strings.Split(pkt.Info, ":")
					}
				}
			}
		case "ip", "ipv6":
			for _, f := range proto.Fields {
				switch f.Name {
				case "ip.src", "ipv6.src":
					if pkt.Src == "" {
						pkt.Src = f.Show
					}
				case "ip.dst", "ipv6.dst":
					if pkt.Dst == "" {
						pkt.Dst = f.Show
					}
				}
			}
		}
	}

	// Determine top-level protocol
	pkt.Protocol = detectProtocol(pkt.Layers)
	return pkt
}

func convertField(f pdmlField) Field {
	out := Field{
		Name:      f.Name,
		ShowName:  f.ShowName,
		ShowValue: f.Show,
		Value:     f.Value,
	}
	for _, child := range f.Children {
		out.Children = append(out.Children, convertField(child))
	}
	return out
}

func detectProtocol(layers map[string]Layer) string {
	priority := []string{"gsm_map", "cap", "tcap", "sccp", "mtp3", "m3ua", "sctp", "tcp", "udp", "ip"}
	for _, p := range priority {
		if _, ok := layers[p]; ok {
			return p
		}
	}
	return "unknown"
}

// FieldValue looks up the "show" value of a named field within a layer.
func FieldValue(layer Layer, name string) string {
	for _, f := range layer.Fields {
		if f.Name == name {
			return f.ShowValue
		}
		if v := searchChildren(f.Children, name); v != "" {
			return v
		}
	}
	return ""
}

func searchChildren(fields []Field, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.ShowValue
		}
		if v := searchChildren(f.Children, name); v != "" {
			return v
		}
	}
	return ""
}

// FieldShowName looks up the "showname" of a named field within a layer.
func FieldShowName(layer Layer, name string) string {
	for _, f := range layer.Fields {
		if f.Name == name {
			return f.ShowName
		}
		if v := searchChildrenShowName(f.Children, name); v != "" {
			return v
		}
	}
	return ""
}

func searchChildrenShowName(fields []Field, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.ShowName
		}
		if v := searchChildrenShowName(f.Children, name); v != "" {
			return v
		}
	}
	return ""
}
