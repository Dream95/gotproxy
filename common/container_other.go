//go:build !linux

package common

import (
	"context"
	"fmt"
	"net"
)

type ContainerNamespaces struct {
	PidNS uint32
	MntNS uint32
	NetNS uint32
}

func ResolveContainerNamespacesByName(_ context.Context, _ string) (ContainerNamespaces, error) {
	return ContainerNamespaces{}, fmt.Errorf("container filtering requires Linux")
}

func ResolveDockerBridgeGatewayIPv4(_ context.Context) (net.IP, error) {
	return nil, fmt.Errorf("docker bridge gateway discovery requires Linux")
}
