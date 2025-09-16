package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func VlessSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}

	tlsOptions := getTLSOptions(decoded)
	if tlsOptions.TLS != nil {
		if security := decoded["security"]; security == "reality" {
			tlsOptions.TLS.Reality = &T.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: decoded["pbk"],
				ShortID:   decoded["sid"],
			}
		}
	}

	packetEncoding := decoded["packetencoding"]
	packetEncodingPtr := &packetEncoding

	opts := &T.VLESSOutboundOptions{
		DialerOptions:               getDialerOptions(decoded),
		ServerOptions:               u.GetServerOption(),
		UUID:                        u.Username,
		PacketEncoding:              packetEncodingPtr,
		Flow:                        decoded["flow"],
		OutboundTLSOptionsContainer: tlsOptions,
		Transport:                   transportOptions,
		Multiplex:                   getMuxOptions(decoded),
	}
	return newOutbound(C.TypeVLESS, u.Name, opts), nil
}
