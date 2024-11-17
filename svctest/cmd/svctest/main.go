package main

import (
	"context"
	"fmt"

	"github.com/scionproto/scion/daemon/config"
	"github.com/scionproto/scion/private/app/launcher"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig: &globalCfg,
		ShortName:  "SCION Test Service",
		Main:       realMain,
	}
	application.Run()
}

func realMain(ctx context.Context) error {
	fmt.Println("realMain running")
	defer cleanup()
	<-ctx.Done()
	return nil
}

func cleanup() {
	fmt.Println("Performing cleanup")
}
