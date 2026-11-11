package atrust

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

func (c *Client) getIP() error {
	addr := c.BestNodes[c.MajorNodeGroup]
	if addr == "" {
		for _, node := range c.BestNodes {
			addr = node
			break
		}
	}
	if addr == "" {
		return fmt.Errorf("no reachable node for ip request")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.underlayDialer.DialTLSContext(ctx, "tcp", addr, tunnelTLSConfig())
	if err != nil {
		return err
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	req, err := json.Marshal(authRequestSID{Sid: c.SID})
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	packet := wrapAuthReqData(req, 1)
	if _, err := conn.Write(packet); err != nil {
		return err
	}

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		return fmt.Errorf("failed to read auth method: %w", err)
	}
	if method[0] != l3Version || method[1] != 0xD0 {
		return fmt.Errorf("l3-tunnel unexpected auth method resp: %02x %02x", method[0], method[1])
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read auth header: %w", err)
	}
	if header[0] != 0x53 {
		return fmt.Errorf("l3-tunnel unexpected auth resp version: 0x%02x", header[0])
	}
	status := header[1]
	length := int(binary.BigEndian.Uint16(header[2:4]))
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return fmt.Errorf("failed to read auth payload: %w", err)
		}
	}
	if status != 0 {
		return fmt.Errorf("l3-tunnel tunnel auth status %d", status)
	}
	if len(payload) > 0 {
		var resp authResponseSID
		if err := json.Unmarshal(payload, &resp); err != nil {
			return fmt.Errorf("failed to unmarshal auth resp: %w", err)
		}
		if resp.Code != 0 {
			return fmt.Errorf("l3-tunnel tunnel auth failed: %d %s", resp.Code, resp.Message)
		}
	}

	vipHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, vipHeader); err != nil {
		return fmt.Errorf("failed to read vip header: %w", err)
	}
	dataLen, err := parseInitialVIPHeader(vipHeader)
	if err != nil {
		return fmt.Errorf("failed to parse vip header: %w", err)
	}
	vipData := make([]byte, dataLen)
	if _, err := io.ReadFull(conn, vipData); err != nil {
		return fmt.Errorf("failed to read vip data: %w", err)
	}

	ips := parseVirtualIPData(vipData)
	if len(ips) == 0 {
		return fmt.Errorf("no virtual IP received from server")
	}

	c.setIP(ips[0])
	log.Printf("Received IP: %s", ips[0].String())
	return nil
}
