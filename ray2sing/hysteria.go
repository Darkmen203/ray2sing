package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func HysteriaSingbox(hysteriaURL string) (*T.Outbound, error) {
	u, err := ParseUrl(hysteriaURL, 443)
	if err != nil {
		return nil, err
	}
	SNI := u.Params["peer"]
	opts := &T.HysteriaOutboundOptions{
		ServerOptions: u.GetServerOption(),
		OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				DisableSNI: isIPOnly(SNI),
				ServerName: SNI,
				Insecure:   u.Params["insecure"] == "1",
			},
		},
	}

	return newOutbound(C.TypeHysteria, u.Name, opts), nil
}
