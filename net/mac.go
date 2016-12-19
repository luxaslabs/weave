package net

import (
	"crypto/rand"
	"crypto/sha256"
	"net"
)

func RandomMAC() (net.HardwareAddr, error) {
	mac := make([]byte, 6)
	if _, err := rand.Read(mac); err != nil {
		return nil, err
	}

	setUnicastAndLocal(mac)

	return net.HardwareAddr(mac), nil
}

func PersistentMAC(uuid []byte) net.HardwareAddr {
	hash := sha256.New()
	hash.Write([]byte("9oBJ0Jmip-"))
	hash.Write(uuid)
	sum := hash.Sum(nil)

	setUnicastAndLocal(sum)

	return net.HardwareAddr(sum[:6])
}

func setUnicastAndLocal(mac []byte) {
	mac[0] = (mac[0] & 0xFE) | 0x02
}
