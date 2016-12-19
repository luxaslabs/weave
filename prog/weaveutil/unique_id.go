package main

import (
	"fmt"

	"github.com/weaveworks/weave/common"
)

func uniqueID(args []string) error {
	if len(args) > 0 {
		cmdUsage("unique-id", "")
	}
	uid, err := common.GetSystemPeerName("")
	if err != nil {
		return err
	}
	fmt.Printf(uid)
	return nil
}
