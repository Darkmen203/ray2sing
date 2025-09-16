package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func TrojanSingbox(trojanURL string) (*T.Outbound, error) {
	u, err := ParseUrl(trojanURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}

	opts := &T.TrojanOutboundOptions{
		DialerOptions:               getDialerOptions(decoded),
		ServerOptions:               u.GetServerOption(),
		Password:                    u.Username,
		OutboundTLSOptionsContainer: getTLSOptions(decoded),
		Transport:                   transportOptions,
		Multiplex:                   getMuxOptions(decoded),
	}
	return newOutbound(C.TypeTrojan, u.Name, opts), nil
}
