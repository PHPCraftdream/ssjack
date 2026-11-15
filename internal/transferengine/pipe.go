package transferengine

import "io"

// pipeStream runs producer in a goroutine writing one end of an io.Pipe and
// consumes the other end with consume. A producer failure is carried into
// the consumer through the pipe (CloseWithError); a consumer failure or any
// early return closes the read end, so a producer blocked in Write cannot
// deadlock. The producer is always waited for before pipeStream returns, so
// no goroutine outlives the transfer step. Callers decide the outcome from
// the consumer side first: a producer error that never reached the consumer
// is the aftermath of the consumer's own failure.
func pipeStream(producer func(io.Writer) error, consume func(io.Reader) error) (consumerErr, producerErr error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := producer(pw)
		if err != nil {
			_ = pw.CloseWithError(err)
		} else {
			_ = pw.Close()
		}
		done <- err
	}()
	consumerErr = consume(pr)
	_ = pr.Close()
	producerErr = <-done
	return consumerErr, producerErr
}
