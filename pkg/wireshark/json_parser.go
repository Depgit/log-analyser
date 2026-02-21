package wireshark

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// wsJSON represents the top-level structure of tshark -T json output.
type wsJSON []wsJSONPacket

type wsJSONPacket struct {
	Source struct {
		Layers map[string]json.RawMessage `json:"layers"`
	} `json:"_source"`
}

// ParseJSON reads a tshark JSON export and returns a slice of Packets.
func ParseJSON(r io.Reader) ([]Packet, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var raw wsJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	packets := make([]Packet, 0, len(raw))
	for i, wp := range raw {
		pkt := Packet{
			FrameNum: i + 1,
			Layers:   make(map[string]Layer),
		}

		for protoName, rawLayer := range wp.Source.Layers {
			// Each layer is a JSON object with field-name → value mappings
			var flatFields map[string]interface{}
			if err := json.Unmarshal(rawLayer, &flatFields); err != nil {
				continue
			}
			layer := Layer{Name: protoName}
			for k, v := range flatFields {
				var strVal string
				switch tv := v.(type) {
				case string:
					strVal = tv
				default:
					b, _ := json.Marshal(tv)
					strVal = string(b)
				}
				layer.Fields = append(layer.Fields, Field{
					Name:      k,
					ShowValue: strVal,
					Value:     strVal,
				})
			}
			pkt.Layers[protoName] = layer

			// Extract common frame/ip fields
			switch protoName {
			case "frame":
				pkt.FrameNum = intField(flatFields, "frame.number", i+1)
				pkt.TimeEpoch = strField(flatFields, "frame.time_epoch")
				pkt.TimeRel = strField(flatFields, "frame.time_relative")
				pkt.Length = intField(flatFields, "frame.len", 0)
				pkt.Info = strField(flatFields, "frame.protocols")
				if pkt.Info != "" {
					pkt.Protocols = strings.Split(pkt.Info, ":")
				}
			case "ip", "ipv6":
				if pkt.Src == "" {
					pkt.Src = strField(flatFields, "ip.src")
					if pkt.Src == "" {
						pkt.Src = strField(flatFields, "ipv6.src")
					}
				}
				if pkt.Dst == "" {
					pkt.Dst = strField(flatFields, "ip.dst")
					if pkt.Dst == "" {
						pkt.Dst = strField(flatFields, "ipv6.dst")
					}
				}
			}
		}

		pkt.Protocol = detectProtocol(pkt.Layers)
		packets = append(packets, pkt)
	}
	return packets, nil
}

func strField(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intField(m map[string]interface{}, key string, def int) int {
	if v, ok := m[key]; ok {
		switch tv := v.(type) {
		case float64:
			return int(tv)
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(tv)); err == nil {
				return n
			}
		}
	}
	return def
}
