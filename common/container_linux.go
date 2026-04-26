//go:build linux

package common

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultDockerSocket = "/var/run/docker.sock"

type ContainerNamespaces struct {
	PidNS uint32
	MntNS uint32
	NetNS uint32
}

type dockerContainerSummary struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
}

type dockerContainerInspect struct {
	State struct {
		Pid int `json:"Pid"`
	} `json:"State"`
}

type dockerNetworkInspect struct {
	IPAM struct {
		Config []struct {
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
}

func ResolveContainerNamespacesByName(ctx context.Context, name string) (ContainerNamespaces, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ContainerNamespaces{}, fmt.Errorf("container name cannot be empty")
	}

	client, err := newDockerHTTPClient(defaultDockerSocket)
	if err != nil {
		return ContainerNamespaces{}, err
	}

	containers, err := dockerListContainers(ctx, client)
	if err != nil {
		return ContainerNamespaces{}, err
	}

	var matched []dockerContainerSummary
	for _, c := range containers {
		for _, n := range c.Names {
			if strings.TrimPrefix(n, "/") == name {
				matched = append(matched, c)
				break
			}
		}
	}

	if len(matched) == 0 {
		return ContainerNamespaces{}, fmt.Errorf("no running container found by name %q", name)
	}
	if len(matched) > 1 {
		return ContainerNamespaces{}, fmt.Errorf("found more than one running container by name %q", name)
	}

	pid, err := dockerInspectContainerPID(ctx, client, matched[0].ID)
	if err != nil {
		return ContainerNamespaces{}, err
	}
	if pid <= 0 {
		return ContainerNamespaces{}, fmt.Errorf("container %q has invalid pid %d", name, pid)
	}

	ns, err := readNamespacesFromPID(pid)
	if err != nil {
		return ContainerNamespaces{}, err
	}
	return ns, nil
}

func newDockerHTTPClient(socketPath string) (*http.Client, error) {
	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("docker socket %s not available: %w", socketPath, err)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}, nil
}

func dockerListContainers(ctx context.Context, client *http.Client) ([]dockerContainerSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/containers/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker list containers failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("docker list containers returned status %s", resp.Status)
	}

	var containers []dockerContainerSummary
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("decode docker containers response: %w", err)
	}
	return containers, nil
}

func dockerInspectContainerPID(ctx context.Context, client *http.Client, containerID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/containers/"+containerID+"/json", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("docker inspect failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("docker inspect returned status %s", resp.Status)
	}

	var inspect dockerContainerInspect
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return 0, fmt.Errorf("decode docker inspect response: %w", err)
	}
	return inspect.State.Pid, nil
}

func ResolveDockerBridgeGatewayIPv4(ctx context.Context) (net.IP, error) {
	client, err := newDockerHTTPClient(defaultDockerSocket)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/networks/bridge", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker inspect bridge network failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("docker inspect bridge network returned status %s", resp.Status)
	}

	var inspect dockerNetworkInspect
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return nil, fmt.Errorf("decode docker bridge network response: %w", err)
	}
	if len(inspect.IPAM.Config) == 0 {
		return nil, fmt.Errorf("docker bridge network has no IPAM config")
	}
	gateway := strings.TrimSpace(inspect.IPAM.Config[0].Gateway)
	if gateway == "" {
		return nil, fmt.Errorf("docker bridge network gateway is empty")
	}
	ip := net.ParseIP(gateway).To4()
	if ip == nil {
		return nil, fmt.Errorf("docker bridge gateway %q is not an IPv4 address", gateway)
	}
	return ip, nil
}

func readNamespacesFromPID(pid int) (ContainerNamespaces, error) {
	base := fmt.Sprintf("/proc/%d/ns", pid)
	pidNS, err := readNamespaceInode(base + "/pid")
	if err != nil {
		return ContainerNamespaces{}, err
	}
	mntNS, err := readNamespaceInode(base + "/mnt")
	if err != nil {
		return ContainerNamespaces{}, err
	}
	netNS, err := readNamespaceInode(base + "/net")
	if err != nil {
		return ContainerNamespaces{}, err
	}
	return ContainerNamespaces{
		PidNS: pidNS,
		MntNS: mntNS,
		NetNS: netNS,
	}, nil
}

func readNamespaceInode(path string) (uint32, error) {
	link, err := os.Readlink(path)
	if err != nil {
		return 0, fmt.Errorf("readlink %s: %w", path, err)
	}
	left := strings.IndexByte(link, '[')
	right := strings.IndexByte(link, ']')
	if left < 0 || right <= left+1 {
		return 0, fmt.Errorf("unexpected namespace link format %q", link)
	}
	id, err := strconv.ParseUint(link[left+1:right], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse namespace inode %q: %w", link, err)
	}
	return uint32(id), nil
}
