// package IPsec provides primitives for establishing IPsec in the fastdp mode.
//
// The implementation is based on the kernel IP packet transformation framework
// called XFRM. Unfortunately, docs are barely existing and the complexity of
// the framework is high. The best resource I found is Chapter 10 in
// "Linux Kernel Networking: Implementation and Theory" by Rami Rosen.
//
// At the high level, we use the ESP protocol in the Transport mode. Each packet
// is encrypted with "rfc4106(gcm(aes))", with 32 bytes key and 4 bytes salt.
// For each connection direction different key is used. An IPsec connection
// between two peers is identified by directional SPIs formed by concatenating
// `fromPeerShortID` and `toPeerShortID`.
//
// To establish IPsec between peer A and B we need to do the following on each
// peer:
//
//      1. Create (inbound) SA which determines how to process (decrypt) an
//         incoming packet from the remote peer.
//      2. Create (outbound) SA for encrypting a packet destined to the remote
//         peer.
//      3. Create XFRM policy which says what SA to apply for an outgoing packet.
//      4. Install iptables rules for marking the vxlan-tunneled outbound
//         traffic.
//
// The kernel VXLAN driver does not set a dst port of a tunnel in the ip flow
// descriptor, thus xfrm policy lookup cannot match a policy which includes
// the dst port. To work around, we mark outgoing over the tunnel packets with
// iptables and set the same mark in the policy selector (funnily enough,
// iptables_mangle module eventually sets the missing dst port in the flow
// descriptor). The challenge here is to pick such a mark that it would not
// interfere with other networking applications before OUTPUT'ing a packet. For
// example, k8s by default uses 1<<14 and 1<<15 marks.
package ipsec

// TODO(mp)
// * Document passwd derivation.
// * Document MTU requirements.
// * Test NAT-T in tunnel mode.
// * Blogpost (w/ benchmarks)
//
// * Various XFRM related improvements to vishvananda/netlink.
// * Patch the kernel.
// * Extend the heartbeats to check whether encryption is properly set.
// * Rotate keys.

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/weaveworks/mesh"
)

type SPI uint32

const (
	mark    = uint32(0x1) << 17
	markStr = "0x20000/0x20000"

	table     = "mangle"
	markChain = "WEAVE-IPSEC-MARK"
	mainChain = "WEAVE-IPSEC"
)

// IPSec

type IPSec struct {
	sync.RWMutex
	ipt *iptables.IPTables
	rc  *connRefCount
}

func New() (*IPSec, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, errors.Wrap(err, "iptables new")
	}

	ipsec := &IPSec{
		ipt: ipt,
		rc:  newConnRefCount(),
	}

	return ipsec, nil
}

// Protect establishes IPsec between given peers.
func (ipsec *IPSec) Protect(srcPeer, dstPeer mesh.PeerShortID, srcIP, dstIP net.IP, dstPort int, localKey, remoteKey []byte) (SPI, error) {
	outSPI, err := newSPI(srcPeer, dstPeer)
	if err != nil {
		return 0,
			errors.Wrap(err, fmt.Sprintf("derive SPI (%x, %x)", srcPeer, dstPeer))
	}

	if ipsec.rc.get(srcIP, dstIP, outSPI) > 1 {
		// IPSec has been already set up between the given peers
		return outSPI, nil
	}

	inSPI, err := newSPI(dstPeer, srcPeer)
	if err != nil {
		return 0,
			errors.Wrap(err, fmt.Sprintf("derive SPI (%x, %x)", dstPeer, srcPeer))
	}

	ipsec.Lock()
	defer ipsec.Unlock()

	if inSA, err := xfrmState(dstIP, srcIP, inSPI, remoteKey); err == nil {
		if err := netlink.XfrmStateAdd(inSA); err != nil {
			return 0,
				errors.Wrap(err, fmt.Sprintf("xfrm state add (in, %s, %s, 0x%x)", inSA.Src, inSA.Dst, inSA.Spi))
		}
	} else {
		return 0, errors.Wrap(err, "new xfrm state (in)")
	}

	if outSA, err := xfrmState(srcIP, dstIP, outSPI, localKey); err == nil {
		if err := netlink.XfrmStateAdd(outSA); err != nil {
			return 0,
				errors.Wrap(err, fmt.Sprintf("xfrm state add (out, %s, %s, 0x%x)", outSA.Src, outSA.Dst, outSA.Spi))
		}
	} else {
		return 0, errors.Wrap(err, "new xfrm state (out)")
	}

	outPolicy := xfrmPolicy(srcIP, dstIP, outSPI)
	if err := netlink.XfrmPolicyAdd(outPolicy); err != nil {
		return 0,
			errors.Wrap(err, fmt.Sprintf("xfrm policy add (%s, %s, 0x%x)", srcIP, dstIP, outSPI))
	}

	if err := ipsec.installMarkRule(srcIP, dstIP, dstPort); err != nil {
		return 0,
			errors.Wrap(err, fmt.Sprintf("install mark rule (%s, %s, 0x%x)", srcIP, dstIP, dstPort))
	}

	return outSPI, nil
}

// Destroy tears down the previously established IPsec between two peers.
func (ipsec *IPSec) Destroy(srcIP, dstIP net.IP, dstPort int, outSPI SPI) error {
	var err error

	ipsec.Lock()
	defer ipsec.Unlock()

	count := ipsec.rc.put(srcIP, dstIP, outSPI)
	switch {
	case count > 0:
		return nil
	case count < 0:
		return fmt.Errorf("IPSec invalid state")
	}

	if err = netlink.XfrmPolicyDel(xfrmPolicy(srcIP, dstIP, outSPI)); err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("xfrm policy del (%s, %s, 0x%x)", srcIP, dstIP, outSPI))
	}

	inSA := &netlink.XfrmState{
		Src:   srcIP,
		Dst:   dstIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(outSPI),
	}
	outSA := &netlink.XfrmState{
		Src:   dstIP,
		Dst:   srcIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(reverseSPI(outSPI)),
	}
	if err = netlink.XfrmStateDel(inSA); err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("xfrm state del (in, %s, %s, 0x%x)", inSA.Src, inSA.Dst, inSA.Spi))
	}
	if err = netlink.XfrmStateDel(outSA); err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("xfrm state del (out, %s, %s, 0x%x)", outSA.Src, outSA.Dst, outSA.Spi))
	}

	if err = ipsec.removeMarkRule(srcIP, dstIP, dstPort); err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("remove mark rule (%s, %s, %d)", srcIP, dstIP, dstPort))
	}

	return nil
}

// Flush removes all policies/SAs established by us. Also, it removes chains and
// rules of iptables used for the marking. If destroy is true, the chains and
// the marking rule won't be re-created.
func (ipsec *IPSec) Flush(destroy bool) error {
	ipsec.Lock()
	defer ipsec.Unlock()

	spis := make(map[SPI]struct{})

	policies, err := netlink.XfrmPolicyList(syscall.AF_INET)
	if err != nil {
		return errors.Wrap(err, "xfrm policy list")
	}
	for _, p := range policies {
		if p.Mark != nil && p.Mark.Value == mark && len(p.Tmpls) != 0 {
			spi := SPI(p.Tmpls[0].Spi)
			spis[spi] = struct{}{}
			spis[reverseSPI(spi)] = struct{}{}

			if err := netlink.XfrmPolicyDel(&p); err != nil {
				return errors.Wrap(err, fmt.Sprintf("xfrm policy del (%s, %s, 0x%x)", p.Src, p.Dst, spi))
			}
		}
	}

	states, err := netlink.XfrmStateList(syscall.AF_INET)
	if err != nil {
		return errors.Wrap(err, "xfrm state list")
	}
	for _, s := range states {
		if _, ok := spis[SPI(s.Spi)]; ok {
			if err := netlink.XfrmStateDel(&s); err != nil {
				return errors.Wrap(err, fmt.Sprintf("xfrm state list (%s, %s, 0x%x)", s.Src, s.Dst, s.Spi))
			}
		}
	}

	if err := ipsec.resetIPTables(destroy); err != nil {
		return errors.Wrap(err, "reset ip tables")
	}

	return nil
}

// connRefCount

// Reference counting for IPsec establishments.
//
// Mesh might simultaneously create two connections for the same peer pair which
// could result in establishing IPsec multiple times.
type connRefCount struct {
	ref map[[12]byte]int
}

func newConnRefCount() *connRefCount {
	return &connRefCount{ref: make(map[[12]byte]int)}
}

func (rc *connRefCount) get(srcIP, dstIP net.IP, spi SPI) int {
	key := connRefKey(srcIP, dstIP, spi)
	rc.ref[key]++

	return rc.ref[key]
}

func (rc *connRefCount) put(srcIP, dstIP net.IP, spi SPI) int {
	key := connRefKey(srcIP, dstIP, spi)
	rc.ref[key]--

	return rc.ref[key]
}

// iptables

func (ipsec *IPSec) installMarkRule(srcIP, dstIP net.IP, dstPort int) error {
	rulespec := markRulespec(srcIP, dstIP, dstPort)
	if err := ipsec.ipt.AppendUnique(table, mainChain, rulespec...); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables append (%s, %s, %s)", table, mainChain, rulespec))
	}

	return nil
}

func (ipsec *IPSec) removeMarkRule(srcIP, dstIP net.IP, dstPort int) error {
	rulespec := markRulespec(srcIP, dstIP, dstPort)
	if err := ipsec.ipt.Delete(table, mainChain, rulespec...); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables delete (%s, %s, %s)", table, mainChain, rulespec))
	}

	return nil
}

func markRulespec(srcIP, dstIP net.IP, dstPort int) []string {
	return []string{
		"-s", srcIP.String(), "-d", dstIP.String(),
		"-p", "udp", "--dport", strconv.FormatUint(uint64(dstPort), 10),
		"-j", markChain,
	}

}

func (ipsec *IPSec) resetIPTables(destroy bool) error {
	if err := ipsec.ipt.ClearChain(table, mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables clear (%s, %s)", table, mainChain))
	}

	if err := ipsec.ipt.ClearChain(table, markChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables clear (%s, %s)", table, markChain))
	}

	if err := ipsec.ipt.AppendUnique(table, "OUTPUT", "-j", mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables append (%s, %s)", table, "OUTPUT"))
	}

	if !destroy {
		rulespec := []string{"-j", "MARK", "--set-xmark", markStr}
		if err := ipsec.ipt.Append(table, markChain, rulespec...); err != nil {
			return errors.Wrap(err, fmt.Sprintf("iptables append (%s, %s, %s)", table, markChain, rulespec))
		}

		return nil
	}

	if err := ipsec.ipt.Delete(table, "OUTPUT", "-j", mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables delete (%s, %s)", table, "OUTPUT"))
	}

	if err := ipsec.ipt.DeleteChain(table, mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables delete (%s, %s)", table, mainChain))
	}

	if err := ipsec.ipt.DeleteChain(table, markChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables delete (%s, %s)", table, mainChain))
	}

	return nil
}

// xfrm

func xfrmState(srcIP, dstIP net.IP, spi SPI, key []byte) (*netlink.XfrmState, error) {
	if len(key) != 36 {
		return nil, fmt.Errorf("key should be 36 bytes long")
	}

	return &netlink.XfrmState{
		Src:   srcIP,
		Dst:   dstIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TRANSPORT,
		Spi:   int(spi),
		Aead: &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    key,
			ICVLen: 128,
		},
	}, nil
}

func xfrmPolicy(srcIP, dstIP net.IP, spi SPI) *netlink.XfrmPolicy {
	ipMask := []byte{0xff, 0xff, 0xff, 0xff} // /32

	return &netlink.XfrmPolicy{
		Src:   &net.IPNet{IP: srcIP, Mask: ipMask},
		Dst:   &net.IPNet{IP: dstIP, Mask: ipMask},
		Proto: syscall.IPPROTO_UDP,
		Dir:   netlink.XFRM_DIR_OUT,
		Mark: &netlink.XfrmMark{
			Value: mark,
			Mask:  mark,
		},
		Tmpls: []netlink.XfrmPolicyTmpl{
			{
				Src:   srcIP,
				Dst:   dstIP,
				Proto: netlink.XFRM_PROTO_ESP,
				Mode:  netlink.XFRM_MODE_TRANSPORT,
				Spi:   int(spi),
			},
		},
	}
}

// Helpers

func newSPI(srcPeer, dstPeer mesh.PeerShortID) (SPI, error) {
	if mesh.PeerShortIDBits > 16 { // should not happen
		return 0, fmt.Errorf("PeerShortID too long")
	}

	return SPI(uint32(srcPeer)<<16 | uint32(dstPeer)), nil
}

func reverseSPI(spi SPI) SPI {
	return SPI(uint32(spi)>>16 | uint32(spi)<<16)
}

func connRefKey(srcIP, dstIP net.IP, spi SPI) (key [12]byte) {
	copy(key[:], srcIP.To4())
	copy(key[4:], dstIP.To4())
	binary.BigEndian.PutUint32(key[8:], uint32(spi))

	return
}
