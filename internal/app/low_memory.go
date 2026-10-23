package app

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/codejavu-llc/saase/v2/internal/engine"
	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/output"
	"github.com/codejavu-llc/saase/v2/internal/target"
)

func runLowMemoryScan(ctx context.Context, scanner *engine.Scanner, targets []target.Target, options scanOptions, stdout, stderr io.Writer) error {
	spool, err := output.NewSpool()
	if err != nil {
		return fmt.Errorf("create result spool: %w", err)
	}
	defer spool.Close()
	stopCleanup := context.AfterFunc(ctx, spool.Close)
	defer stopCleanup()
	scanner.SetEventHandler(func(event model.ScanEvent) {
		if options.progress && event.DNSProgress != nil {
			writeDNSProgress(stderr, *event.DNSProgress)
		}
	})
	var spoolErr error
	report, scanErr := scanner.ScanTo(ctx, targets, options.providers, func(findings []model.Finding, errors []model.ProbeError) error {
		spoolErr = spool.Add(findings, errors)
		if spoolErr != nil {
			return spoolErr
		}
		if options.verbose {
			for _, e := range errors {
				_, _ = fmt.Fprintf(stderr, "[!] %s %s: %s\n", e.Detector, e.Subject, e.Message)
			}
		}
		return nil
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if spoolErr != nil {
		return spoolErr
	}
	if scanErr != nil && spool.FindingCount == 0 {
		return scanErr
	}
	destination := stdout
	var file *os.File
	if options.outputFile != "" {
		file, err = os.Create(options.outputFile)
		if err != nil {
			return fmt.Errorf("create output %q: %w", options.outputFile, err)
		}
		defer file.Close()
		destination = io.MultiWriter(stdout, file)
	}
	if err := spool.Write(destination, report.Metadata, options.format); err != nil {
		return err
	}
	if file != nil {
		if err := file.Close(); err != nil {
			return err
		}
	}
	if scanErr == nil && spool.FindingCount == 0 && scanner.PrimaryDNSChecks() > 0 && spool.ErrorCount >= len(targets)*scanner.PrimaryDNSChecks() {
		return exitError{code: 2, err: fmt.Errorf("scan completed but all primary discovery probes failed")}
	}
	return scanErr
}
