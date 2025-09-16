package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	badoption "github.com/sagernet/sing/common/json/badoption"

	"time"
)

func TuicSingbox(tuicUrl string) (*T.Outbound, error) {
	u, err := ParseUrl(tuicUrl, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	valECH, hasECH := decoded["ech"]
	hasECH = hasECH && (valECH != "0")
	var echOpts *T.OutboundECHOptions
	if hasECH {
		echOpts = &T.OutboundECHOptions{Enabled: true}
	}

	opts := &T.TUICOutboundOptions{
		ServerOptions:     u.GetServerOption(),
		UUID:              u.Username,
		Password:          u.Password,
		CongestionControl: decoded["congestioncontrol"],
		UDPRelayMode:      decoded["udprelaymode"],
		ZeroRTTHandshake:  false,
		Heartbeat:         badoption.Duration(10 * time.Second),
		OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				DisableSNI: decoded["sni"] == "",
				ServerName: decoded["sni"],
				Insecure:   decoded["allowinsecure"] == "1" || decoded["insecure"] == "1",
				ALPN:       []string{"h3", "spdy/3.1"},
				ECH:        echOpts,
			},
		},
	}

	return newOutbound(C.TypeTUIC, u.Name, opts), nil
}
