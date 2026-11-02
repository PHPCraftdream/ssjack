package apptransport

import "context"

func reverseRequestContext(toolCtx, requestCtx context.Context) (context.Context, func()) {
	if requestCtx == nil {
		return context.WithCancel(toolCtx)
	}

	requestDeadline, hasRequestDeadline := requestCtx.Deadline()
	toolDeadline, hasToolDeadline := toolCtx.Deadline()

	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if hasRequestDeadline && (!hasToolDeadline || requestDeadline.Before(toolDeadline)) {
		ctx, cancel = context.WithDeadline(toolCtx, requestDeadline)
	} else {
		ctx, cancel = context.WithCancel(toolCtx)
	}

	stop := context.AfterFunc(requestCtx, cancel)
	if requestCtx.Err() != nil {
		cancel()
	}

	cleanup := func() {
		stop()
		cancel()
	}
	return ctx, cleanup
}
