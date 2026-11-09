package vault

func (s *Session) run() {
	defer close(s.done)
	defer func() {
		for {
			select {
			case job := <-s.jobs:
				clear(job.payload)
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.jobs:
			if s.ctx.Err() != nil {
				clear(job.payload)
				return
			}
			s.mu.Lock()
			paused := s.saveErr != nil || job.revision <= s.saved
			s.mu.Unlock()
			if paused {
				clear(job.payload)
				continue
			}
			err := s.save(s.ctx, job.payload)
			clear(job.payload)
			s.mu.Lock()
			if err != nil {
				s.saveErr = err
			} else {
				s.saved = job.revision
				if s.saveDigest != nil {
					s.savedCipher = s.saveDigest()
				}
			}
			s.signal()
			s.mu.Unlock()
		}
	}
}
