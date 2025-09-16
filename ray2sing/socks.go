package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func SocksSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}

	opts := &T.SOCKSOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Username:      u.Username,
		Password:      u.Password,
	}
	if version, err := getOneOf(u.Params, "v", "ver", "version"); err == nil {
		opts.Version = version
	}
	// if net, err := getOneOf(u.Params, "net", "network"); err == nil {
	// 	opts.Network= net
	// }
	return newOutbound(C.TypeSOCKS, u.Name, opts), nil
}
