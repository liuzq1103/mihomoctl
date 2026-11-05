package main

import (
	"fmt"
	"io"
)

// An stdin seed is an already-reviewed preview, not permission to apply it.
func offerPlainPreview(src Source, cli CliSource, in io.Reader, out io.Writer, env Envelope) error {
	c := &plainConsole{src: src, cli: cli, raw: in, out: out}
	for _, line := range previewSummary(env.Data) {
		fmt.Fprintln(out, line)
	}
	yes, e := c.ask("保存并启动？[y/N] ")
	if e != nil {
		return e
	}
	id, sha := stringValue(env.Data["id"]), stringValue(env.Data["sha256"])
	if yes != "y" && yes != "Y" {
		if v, ok := cli.(SubscriptionDiscardCli); ok {
			_, _ = v.SubscriptionDiscard(id)
		}
		return nil
	}
	result, _, e := saveSubscription(cli, id, sha)
	if e != nil {
		return e
	}
	if e = serviceError(result, nil); e != nil {
		return e
	}
	for _, line := range envelopeLines(result) {
		fmt.Fprintln(out, line)
	}
	return nil
}
