package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func HttpSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}

	opts := &T.HTTPOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Username:      u.Username,
		Password:      u.Password,
	}
	if _, err := getOneOf(u.Params, "tls", "sni", "insecure"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS = &T.OutboundTLSOptions{
			Enabled: true,
		}
	}
	if sni, err := getOneOf(u.Params, "sni"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS.ServerName = sni
	}
	if insecure, err := getOneOf(u.Params, "insecure"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS.Insecure = insecure != "0"
	}
	if path, err := getOneOf(u.Params, "path"); err == nil {
		opts.Path = path
	}
	// if net, err := getOneOf(u.Params, "net", "network"); err == nil {
	// 	opts.Network= net
	// }
	return newOutbound(C.TypeHTTP, u.Name, opts), nil
}

func HttpsSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}

	opts := &T.HTTPOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Username:      u.Username,
		Password:      u.Password,
	}
	opts.OutboundTLSOptionsContainer.TLS = &T.OutboundTLSOptions{
		Enabled: true,
	}
	if sni, err := getOneOf(u.Params, "sni"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS.ServerName = sni
	}
	if insecure, err := getOneOf(u.Params, "insecure"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS.Insecure = insecure != "0"
	}

	if path, err := getOneOf(u.Params, "path"); err == nil {
		opts.Path = path
	}

	// if net, err := getOneOf(u.Params, "net", "network"); err == nil {
	// 	opts.Network= net
	// }
	return newOutbound(C.TypeHTTP, u.Name, opts), nil
}
