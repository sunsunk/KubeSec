package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/lima-vm/lima/pkg/autostart"
	networks "github.com/lima-vm/lima/pkg/networks/reconcile"
	"github.com/lima-vm/lima/pkg/stop"
	"github.com/lima-vm/lima/pkg/store"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newDeleteCommand() *cobra.Command {
	deleteCommand := &cobra.Command{
		Use:               "delete INSTANCE [INSTANCE, ...]",
		Aliases:           []string{"remove", "rm"},
		Short:             "Delete an instance of Lima.",
		Args:              WrapArgsError(cobra.MinimumNArgs(1)),
		RunE:              deleteAction,
		ValidArgsFunction: deleteBashComplete,
		GroupID:           basicCommand,
	}
	deleteCommand.Flags().BoolP("force", "f", false, "forcibly kill the processes")
	return deleteCommand
}

func deleteAction(cmd *cobra.Command, args []string) error {
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return err
	}
	for _, instName := range args {
		inst, err := store.Inspect(instName)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				logrus.Warnf("Ignoring non-existent instance %q", instName)
				continue
			}
			return err
		}
		if err := deleteInstance(cmd.Context(), inst, force); err != nil {
			return fmt.Errorf("failed to delete instance %q: %w", instName, err)
		}
		if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
			deleted, err := autostart.DeleteStartAtLoginEntry(runtime.GOOS, instName)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				logrus.WithError(err).Warnf("The autostart file for instance %q does not exist", instName)
			} else if deleted {
				logrus.Infof("The autostart file %q has been deleted", autostart.GetFilePath(runtime.GOOS, instName))
			}
		}
		logrus.Infof("Deleted %q (%q)", instName, inst.Dir)
	}
	return networks.Reconcile(cmd.Context(), "")
}

func deleteInstance(ctx context.Context, inst *store.Instance, force bool) error {
	if inst.Protected {
		return fmt.Errorf("instance is protected to prohibit accidental removal (Hint: use `limactl unprotect`)")
	}
	if !force && inst.Status != store.StatusStopped {
		return fmt.Errorf("expected status %q, got %q", store.StatusStopped, inst.Status)
	}

	stopInstanceForcibly(inst)

	if err := stop.Unregister(ctx, inst); err != nil {
		return fmt.Errorf("failed to unregister %q: %w", inst.Dir, err)
	}

	if err := os.RemoveAll(inst.Dir); err != nil {
		return fmt.Errorf("failed to remove %q: %w", inst.Dir, err)
	}

	return nil
}

func deleteBashComplete(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return bashCompleteInstanceNames(cmd)
}
