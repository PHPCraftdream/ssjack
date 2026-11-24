package stdindrain

// DrainStdin synchronously drains raw standard input after an abnormal secret
// read. Unsupported or redirected inputs are rejected.
func DrainStdin() error { return drainPlatform() }
