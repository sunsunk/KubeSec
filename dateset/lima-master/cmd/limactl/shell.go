package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/alessio/shellescape"
	"github.com/lima-vm/lima/pkg/sshutil"
	"github.com/lima-vm/lima/pkg/store"
	"github.com/mattn/go-isatty"
	"github.com/mattn/go-shellwords"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Environment variable that allows configuring the command (alias) to execute
// in place of the 'ssh' executable.
const envShellSSH = "SSH"

const shellHelp = `Execute shell in Lima

lima command is provided as an alias for limactl shell $LIMA_INSTANCE. $LIMA_INSTANCE defaults to "` + DefaultInstanceName + `".

By default, the first 'ssh' executable found in the host's PATH is used to connect to the Lima instance.
A custom ssh alias can be used instead by setting the $` + envShellSSH + ` environment variable.

Hint: try --debug to show the detailed logs, if it seems hanging (mostly due to some SSH issue).
`

func newShellCommand() *cobra.Command {
	shellCmd := &cobra.Command{
		Use:               "shell [flags] INSTANCE [COMMAND...]",
		Short:             "Execute shell in Lima",
		Long:              shellHelp,
		Args:              WrapArgsError(cobra.MinimumNArgs(1)),
		RunE:              shellAction,
		ValidArgsFunction: shellBashComplete,
		SilenceErrors:     true,
		GroupID:           basicCommand,
	}

	shellCmd.Flags().SetInterspersed(false)

	shellCmd.Flags().String("shell", "", "shell interpreter, e.g. /bin/bash")
	shellCmd.Flags().String("workdir", "", "working directory")
	return shellCmd
}

func shellAction(cmd *cobra.Command, args []string) error {
	// simulate the behavior of double dash
	newArg := []string{}
	if len(args) >= 2 && args[1] == "--" {
		newArg = append(newArg, args[:1]...)
		newArg = append(newArg, args[2:]...)
		args = newArg
	}
	instName := args[0]

	if len(args) >= 2 {
		switch args[1] {
		case "create", "start", "delete", "shell":
			// `lima start` (alias of `limactl $LIMA_INSTANCE start`) is probably a typo of `limactl start`
			logrus.Warnf("Perhaps you meant `limactl %s`?", strings.Join(args[1:], " "))
		}
	}

	inst, err := store.Inspect(instName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("instance %q does not exist, run `limactl create %s` to create a new instance", instName, instName)
		}
		return err
	}
	if inst.Status == store.StatusStopped {
		return fmt.Errorf("instance %q is stopped, run `limactl start %s` to start the instance", instName, instName)
	}
	y, err := inst.LoadYAML()
	if err != nil {
		return err
	}

	// When workDir is explicitly set, the shell MUST have workDir as the cwd, or exit with an error.
	//
	// changeDirCmd := "cd workDir || exit 1"                  if workDir != ""
	//              := "cd hostCurrentDir || cd hostHomeDir"   if workDir == ""
	var changeDirCmd string
	workDir, err := cmd.Flags().GetString("workdir")
	if err != nil {
		return err
	}
	if workDir != "" {
		changeDirCmd = fmt.Sprintf("cd %s || exit 1", shellescape.Quote(workDir))
		// FIXME: check whether y.Mounts contains the home, not just len > 0
	} else if len(y.Mounts) > 0 {
		hostCurrentDir, err := os.Getwd()
		if err == nil {
			changeDirCmd = fmt.Sprintf("cd %s", shellescape.Quote(hostCurrentDir))
		} else {
			changeDirCmd = "false"
			logrus.WithError(err).Warn("failed to get the current directory")
		}
		hostHomeDir, err := os.UserHomeDir()
		if err == nil {
			changeDirCmd = fmt.Sprintf("%s || cd %s", changeDirCmd, shellescape.Quote(hostHomeDir))
		} else {
			logrus.WithError(err).Warn("failed to get the home directory")
		}
	} else {
		logrus.Debug("the host home does not seem mounted, so the guest shell will have a different cwd")
	}

	if changeDirCmd == "" {
		changeDirCmd = "false"
	}
	logrus.Debugf("changeDirCmd=%q", changeDirCmd)

	shell, err := cmd.Flags().GetString("shell")
	if err != nil {
		return err
	}
	if shell == "" {
		shell = `"$SHELL"`
	} else {
		shell = shellescape.Quote(shell)
	}
	script := fmt.Sprintf("%s ; exec %s --login", changeDirCmd, shell)
	if len(args) > 1 {
		quotedArgs := make([]string, len(args[1:]))
		parsingEnv := true
		for i, arg := range args[1:] {
			if parsingEnv && isEnv(arg) {
				quotedArgs[i] = quoteEnv(arg)
			} else {
				parsingEnv = false
				quotedArgs[i] = shellescape.Quote(arg)
			}
		}
		script += fmt.Sprintf(
			" -c %s",
			shellescape.Quote(strings.Join(quotedArgs, " ")),
		)
	}

	var arg0 string
	var arg0Args []string

	if sshShell := os.Getenv(envShellSSH); sshShell != "" {
		sshShellFields, err := shellwords.Parse(sshShell)
		switch {
		case err != nil:
			logrus.WithError(err).Warnf("Failed to split %s variable into shell tokens. "+
				"Falling back to 'ssh' command", envShellSSH)
		case len(sshShellFields) > 0:
			arg0 = sshShellFields[0]
			if len(sshShellFields) > 1 {
				arg0Args = sshShellFields[1:]
			}
		}
	}

	if arg0 == "" {
		arg0, err = exec.LookPath("ssh")
		if err != nil {
			return err
		}
	}

	sshOpts, err := sshutil.SSHOpts(inst.Dir, *y.SSH.LoadDotSSHPubKeys, *y.SSH.ForwardAgent, *y.SSH.ForwardX11, *y.SSH.ForwardX11Trusted)
	if err != nil {
		return err
	}
	sshArgs := sshutil.SSHArgsFromOpts(sshOpts)
	if isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()) {
		// required for showing the shell prompt: https://stackoverflow.com/a/626574
		sshArgs = append(sshArgs, "-t")
	}
	if _, present := os.LookupEnv("COLORTERM"); present {
		// SendEnv config is cumulative, with already existing options in ssh_config
		sshArgs = append(sshArgs, "-o", "SendEnv=COLORTERM")
	}
	sshArgs = append(sshArgs, []string{
		"-q",
		"-p", strconv.Itoa(inst.SSHLocalPort),
		inst.SSHAddress,
		"--",
		script,
	}...)
	sshCmd := exec.Command(arg0, append(arg0Args, sshArgs...)...)
	sshCmd.Stdin = os.Stdin
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	logrus.Debugf("executing ssh (may take a long)): %+v", sshCmd.Args)

	// TODO: use syscall.Exec directly (results in losing tty?)
	return sshCmd.Run()
}

func shellBashComplete(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return bashCompleteInstanceNames(cmd)
}

func isEnv(arg string) bool {
	return len(strings.Split(arg, "=")) > 1
}

func quoteEnv(arg string) string {
	env := strings.SplitN(arg, "=", 2)
	env[1] = shellescape.Quote(env[1])
	return strings.Join(env, "=")
}
