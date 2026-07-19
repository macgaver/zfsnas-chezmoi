package system

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"zfsnas/internal/config"
)

// snapshotExists returns true if the named snapshot exists on this host.
func snapshotExists(fullSnapName string) bool {
	err := exec.Command("sudo", "zfs", "list", "-t", "snapshot", "-H", fullSnapName).Run()
	return err == nil
}

// RunReplication executes a ZFS send/receive replication job. It:
//  1. Creates a new snapshot (or reuses existingSnap if provided)
//  2. Sends it to the remote host using zfs send | ssh zfs receive
//  3. Returns the new snapshot name so the caller can update task.LastSnap
//
// existingSnap, if non-empty, is the full dataset@snap name of an already-created
// snapshot to replicate — no new snapshot will be created.
// send is called with each line of combined output from the pipeline.
// RunReplication executes a ZFS send/receive replication job.
// existingSnap, if non-empty, is the full "dataset@snapname" of an already-created snapshot.
// Returns the snap-name suffix (the part after "@") so callers can store it as LastSnap.
func RunReplication(task *config.ReplicationTask, send func(string), existingSnap string) (snapSuffix string, err error) {
	var fullSnapName string // dataset@snapname — used in zfs send
	if existingSnap != "" {
		// Reuse the snapshot that was already created (e.g. by the scheduler).
		fullSnapName = existingSnap
		at := strings.LastIndex(fullSnapName, "@")
		if at >= 0 {
			snapSuffix = fullSnapName[at+1:]
		} else {
			snapSuffix = fullSnapName
		}
		send(fmt.Sprintf("Replicating existing snapshot: %s", fullSnapName))
	} else {
		snapSuffix = fmt.Sprintf("zfsnas-rep-%s-%s", task.ID[:8], time.Now().UTC().Format("20060102T150405Z"))
		fullSnapName = task.SourceDataset + "@" + snapSuffix

		// Create the snapshot.
		send(fmt.Sprintf("Creating snapshot: %s", fullSnapName))
		snapArgs := []string{"snapshot"}
		if task.Recursive {
			snapArgs = append(snapArgs, "-r")
		}
		snapArgs = append(snapArgs, fullSnapName)
		if out, snapErr := exec.Command("sudo", append([]string{"zfs"}, snapArgs...)...).CombinedOutput(); snapErr != nil {
			return "", fmt.Errorf("zfs snapshot failed: %w: %s", snapErr, strings.TrimSpace(string(out)))
		}
		send("Snapshot created.")
	}

	// Detect encryption on the source dataset so we can send raw (-w).
	// Raw mode preserves encrypted blocks end-to-end; it also makes -c redundant.
	rawSend := datasetIsEncrypted(task.SourceDataset)
	if rawSend {
		send("Encrypted dataset detected — using raw send (-w)")
	}

	// Build the zfs send command.
	sendArgs := []string{"send"}
	if task.Recursive {
		sendArgs = append(sendArgs, "-R")
	}
	if rawSend {
		sendArgs = append(sendArgs, "-w")
	} else if task.Compressed {
		sendArgs = append(sendArgs, "-c")
	}
	fullSend := true // will stay true if no valid incremental base is found
	if task.LastSnap != "" {
		baseSnap := task.SourceDataset + "@" + task.LastSnap
		if snapshotExists(baseSnap) {
			sendArgs = append(sendArgs, "-I", baseSnap)
			fullSend = false
		} else {
			// Base snapshot was pruned by retention; fall back to a full send.
			// The caller will update LastSnap on success so next run is incremental again.
			fmt.Printf("[replication] incremental base %s missing, falling back to full send\n", baseSnap)
		}
	}
	sendArgs = append(sendArgs, fullSnapName)

	// Build the SSH zfs receive command.
	remoteUser := task.RemoteUser
	if remoteUser == "" {
		remoteUser = "root"
	}
	receiveCmd := fmt.Sprintf("sudo zfs receive -F %s", task.RemoteDataset)
	sshTarget := fmt.Sprintf("%s@%s", remoteUser, task.RemoteHost)

	// For a full send, destroy any snapshots left on the remote by a previously
	// failed replication. Without this, zfs receive refuses to write a full stream
	// onto a dataset that already has snapshots and the task can never recover.
	if fullSend {
		send("Full send: cleaning up remote snapshots before transfer…")
		cleanCmd := fmt.Sprintf(
			`sudo zfs list -H -t snapshot -r -o name %s 2>/dev/null | xargs -r sudo zfs destroy`,
			task.RemoteDataset,
		)
		if out, cleanErr := exec.Command("ssh", "-o", "BatchMode=yes", sshTarget, cleanCmd).CombinedOutput(); cleanErr != nil {
			if msg := strings.TrimSpace(string(out)); msg != "" {
				send("Warning: remote cleanup: " + msg)
			}
		}
	}

	send(fmt.Sprintf("sudo zfs send → ssh %s '%s'", sshTarget, receiveCmd))
	send("─────────────────────────────────────────")

	// Use two separate commands piped together via os.Pipe — no sh -c.
	// StrictHostKeyChecking is intentionally omitted so SSH validates the host key.
	zfsSendCmd := exec.Command("sudo", append([]string{"zfs"}, sendArgs...)...)
	sshCmd := exec.Command("ssh", "-o", "BatchMode=yes", sshTarget, receiveCmd)

	// Wire zfs-send stdout → ssh stdin via an OS pipe.
	dataR, dataW, pipeErr := os.Pipe()
	if pipeErr != nil {
		return "", fmt.Errorf("pipe: %w", pipeErr)
	}
	zfsSendCmd.Stdout = dataW
	sshCmd.Stdin = dataR

	// Capture stderr from each command separately.
	var sendStderr, sshStderr bytes.Buffer
	zfsSendCmd.Stderr = &sendStderr
	sshCmd.Stderr = &sshStderr

	// Start ssh first so it is ready to receive before the stream begins.
	if startErr := sshCmd.Start(); startErr != nil {
		dataR.Close()
		dataW.Close()
		return "", fmt.Errorf("start ssh: %w", startErr)
	}
	if startErr := zfsSendCmd.Start(); startErr != nil {
		dataW.Close()
		dataR.Close()
		sshCmd.Process.Kill()
		sshCmd.Wait()
		return "", fmt.Errorf("start zfs send: %w", startErr)
	}

	// Close parent copies — each child process has its own fd.
	dataW.Close()
	dataR.Close()

	// Wait for zfs send first; its exit closes the pipe which signals ssh EOF.
	sendWaitErr := zfsSendCmd.Wait()
	sshWaitErr := sshCmd.Wait()

	// Relay any captured stderr output.
	for _, l := range strings.Split(strings.TrimSpace(sendStderr.String()), "\n") {
		if strings.TrimSpace(l) != "" {
			send(l)
		}
	}
	for _, l := range strings.Split(strings.TrimSpace(sshStderr.String()), "\n") {
		if strings.TrimSpace(l) != "" {
			send(l)
		}
	}

	// A broken pipe on `zfs send` means the ssh receiver closed the pipe
	// first — i.e. ssh failed (auth/unreachable host, remote `zfs receive`
	// error) and the send is only reporting the downstream symptom. When
	// that's the case, surface the ssh error (the real cause) instead of the
	// misleading "zfs send failed: signal: broken pipe". Only a send failure
	// that is NOT a broken pipe (dataset missing, local permission, …) is
	// reported as a send failure ahead of ssh.
	sendBrokenPipe := sendWaitErr != nil && strings.Contains(sendWaitErr.Error(), "broken pipe")
	if sendWaitErr != nil && !sendBrokenPipe {
		if msg := strings.TrimSpace(sendStderr.String()); msg != "" {
			return "", fmt.Errorf("zfs send failed: %w: %s", sendWaitErr, msg)
		}
		return "", fmt.Errorf("zfs send failed: %w", sendWaitErr)
	}
	if sshWaitErr != nil {
		sshErrMsg := strings.TrimSpace(sshStderr.String())
		if strings.Contains(sshErrMsg, "Host key verification failed") ||
			strings.Contains(sshErrMsg, "REMOTE HOST IDENTIFICATION HAS CHANGED") {
			return "", fmt.Errorf("SSH host key not trusted for %s. Accept it first: ssh-keyscan %s >> ~/.ssh/known_hosts", task.RemoteHost, task.RemoteHost)
		}
		return "", fmt.Errorf("replication failed: %w: %s", sshWaitErr, sshErrMsg)
	}
	// Broken-pipe send with no ssh error recorded (rare): still surface it
	// rather than returning success.
	if sendWaitErr != nil {
		return "", fmt.Errorf("zfs send failed: %w", sendWaitErr)
	}

	return snapSuffix, nil
}
