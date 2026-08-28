package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/codejavu-llc/saase/v2/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(app.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
