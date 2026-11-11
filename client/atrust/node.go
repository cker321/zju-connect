package atrust

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/internal/ping"
	"github.com/mythologyli/zju-connect/log"
)

const pingNum = 3

type NodeGroup struct {
	WAN []string
	LAN []string
}

type nodeGroupsProbeFunc func(map[string][]string) map[string]string

func getBestNodes(nodeGroups map[string]NodeGroup, dialContext func(context.Context, string, string) (net.Conn, error)) map[string]string {
	return selectBestNodes(nodeGroups, func(nodeGroups map[string][]string) map[string]string {
		return getBestReachableNodes(nodeGroups, dialContext)
	})
}

func selectBestNodes(nodeGroups map[string]NodeGroup, probe nodeGroupsProbeFunc) map[string]string {
	wanNodeGroups := make(map[string][]string, len(nodeGroups))
	for group, nodes := range nodeGroups {
		wanNodeGroups[group] = nodes.WAN
	}
	bestNodes := probe(wanNodeGroups)

	fallbackNodeGroups := make(map[string][]string)
	for group, nodes := range nodeGroups {
		if bestNodes[group] == "" && len(nodes.LAN) > 0 {
			fallbackNodeGroups[group] = nodes.LAN
		}
	}

	if len(fallbackNodeGroups) == 0 {
		return bestNodes
	}
	for group, node := range probe(fallbackNodeGroups) {
		bestNodes[group] = node
	}
	return bestNodes
}

func getBestReachableNodes(nodeGroups map[string][]string, dialContext func(context.Context, string, string) (net.Conn, error)) map[string]string {
	bestNodes := make(map[string]string)
	for group, nodes := range nodeGroups {
		if len(nodes) > 0 {
			var pingList []ping.TCPing
			var chList []<-chan struct{}

			for _, node := range nodes {
				parts := strings.Split(node, ":")
				host := parts[0]
				port, err := strconv.Atoi(parts[1])
				if err != nil {
					continue
				}

				tcping := ping.NewTCPing()
				tcping.SetDialContext(dialContext)
				target := ping.Target{
					Protocol: ping.TCP,
					Host:     host,
					Port:     port,
					Counter:  pingNum,
					Interval: time.Duration(0.5 * float64(time.Second)),
					Timeout:  time.Duration(1 * float64(time.Second)),
				}
				tcping.SetTarget(&target)

				pingList = append(pingList, *tcping)
				ch := tcping.Start()
				chList = append(chList, ch)
			}

			for _, ch := range chList {
				<-ch
			}

			bestScore := time.Duration(0)
			bestNode := ""
			for i, tcping := range pingList {
				result := tcping.Result()
				score, reachable := nodeProbeScore(result)
				// Filter out non-tunnel ports (e.g. 1443 web port returned HTTP instead of tunnel protocol)
				nodeParts := strings.Split(nodes[i], ":")
				nodeHost := nodeParts[0]
				nodePort, _ := strconv.Atoi(nodeParts[1])
				if reachable && !isLikelyTunnelPort(nodeHost, nodePort, dialContext) {
					reachable = false
				}
				if reachable && (bestScore == 0 || score < bestScore) {
					bestNode = nodes[i]
					bestScore = score
				}
			}

			if bestNode != "" {
				bestNodes[group] = bestNode
				log.Printf("Best node in group %s: %s with quality score %d ms", group, bestNode, bestScore.Milliseconds())
			}
		}
	}

	return bestNodes
}

func nodeProbeScore(result *ping.Result) (time.Duration, bool) {
	if result == nil || result.SuccessCounter == 0 {
		return 0, false
	}
	penalty := time.Second
	if result.Target != nil && result.Target.Timeout > 0 {
		penalty = result.Target.Timeout
	}
	return result.Avg() + time.Duration(result.Failed())*penalty, true
}

func isLikelyTunnelPort(host string, port int, dialContext func(context.Context, string, string) (net.Conn, error)) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var rawConn net.Conn
	var err error
	if dialContext != nil {
		rawConn, err = dialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	} else {
		var dialer net.Dialer
		rawConn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	if err != nil {
		return true // fallback to allowing if connection failed
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, tunnelTLSConfig())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return true
	}
	defer tlsConn.Close()

	_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
	// Probe with protocol prefix: if server responds with HTTP ("HTTP/1.1 400" starts with 0x48 0x54), it is not a tunnel node.
	if _, err := tlsConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return true
	}
	resp := make([]byte, 2)
	n, err := tlsConn.Read(resp)
	if err == nil && n >= 2 {
		if resp[0] == 'H' && resp[1] == 'T' {
			return false
		}
	}
	return true
}

func (c *Client) updateBestNodes(ctx context.Context, updateBestNodesInterval int) {
	ticker := time.NewTicker(time.Duration(updateBestNodesInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		bestNodes := getBestNodes(c.NodeGroups, c.underlayDialer.DialContext)
		c.BestNodesRWMutex.Lock()
		c.BestNodes = bestNodes
		c.BestNodesRWMutex.Unlock()

		c.l3TunnelMu.Lock()
		tunnel := c.l3Tunnel
		c.l3TunnelMu.Unlock()
		if tunnel != nil {
			tunnel.evictStaleConns(bestNodes, c.MajorNodeGroup)
		}
	}
}
