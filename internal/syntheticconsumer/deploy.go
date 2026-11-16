package main

import (
	"context"
	"flag"
	"io"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
)

// deploy implements the forward subcommand: bounded v1 text hydration, or
// the v2 prepare/execute stream when --stream-references is given. Every
// refusal before dispatch is withheld; there is no fallback between versions.
func deploy(ctx context.Context, args []string) string {
	flags := flag.NewFlagSet("deploy-text", flag.ContinueOnError)
	file := flags.String("file", "", "")
	template := flags.String("template", "", "")
	profile := flags.String("profile", "", "")
	references := flags.String("stream-references", "", "")
	set, ok := parse(flags, args)
	if !ok || *file == "" || *template == "" || *profile == "" || (set["stream-references"] && *references == "") {
		return statusWithheld
	}
	c, ok := connect(*profile)
	if !ok {
		return statusWithheld
	}
	defer c.client.CloseIdleConnections()
	if set["stream-references"] {
		return deployStream(ctx, c, *profile, *file, *template, *references)
	}
	return deployText(ctx, c, *file, *template)
}

func deployText(ctx context.Context, c *connection, file, templatePath string) string {
	template, ok := readText(templatePath, hydrateLimit)
	if !ok {
		return statusWithheld
	}
	id, ok := operationID()
	if !ok {
		return statusWithheld
	}
	result, ok := c.tool(ctx, "text_hydrate", map[string]string{
		"operation_id": id, "file": file, "mode": "hydrate-v1", "template": template,
	}, hydrateReplyLimit)
	if !ok {
		return statusUnknown
	}
	return settled(result.status)
}

// deployStream prepares and then executes one operation over the same held
// template file. Prepare never reaches the target, so any prepare failure is
// withheld; an execute reply that is not exactly correlated is unknown.
func deployStream(ctx context.Context, c *connection, profile, file, templatePath, referencesPath string) string {
	references, ok := readReferences(referencesPath)
	if !ok {
		return statusWithheld
	}
	source, err := os.Open(templatePath)
	if err != nil {
		return statusWithheld
	}
	defer source.Close()
	before, err := source.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return statusWithheld
	}
	id, ok := operationID()
	if !ok {
		return statusWithheld
	}
	header := streamHeader{Format: streamFormat, OperationID: id, Profile: profile, File: file, References: references}
	prepared, ok := c.exchange(ctx, preparePath, header, source)
	if !ok || prepared.Status != "prepared" || !canonicalID(prepared.Ticket) {
		return statusWithheld
	}
	after, err := source.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return statusWithheld
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return statusWithheld
	}
	header.Ticket = prepared.Ticket
	executed, ok := c.exchange(ctx, executePath, header, source)
	if !ok {
		return statusUnknown
	}
	return settled(executed.Status)
}

// exchange sends the header record followed by the framed source and returns
// the correlated metadata reply. The producer goroutine is always joined.
func (c *connection) exchange(ctx context.Context, path string, header streamHeader, source io.Reader) (streamReply, bool) {
	line, ok := header.line()
	if !ok {
		return streamReply{}, false
	}
	reader, writer := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := writer.Write(line)
		if err == nil {
			err = appstoretextstream.Encode(ctx, source, writer, header.OperationID, appstoretextstream.MaxBytes)
		}
		writer.CloseWithError(err)
	}()
	defer func() {
		reader.Close()
		<-done
	}()
	request, err := c.request(ctx, path, streamContentType, reader)
	if err != nil {
		return streamReply{}, false
	}
	response, err := c.client.Do(request)
	if err != nil {
		return streamReply{}, false
	}
	defer response.Body.Close()
	return readReply(response, header.OperationID)
}
