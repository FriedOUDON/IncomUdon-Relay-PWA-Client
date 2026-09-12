package main

// mediaReplayState is held per sender because a verified CODEC_CONFIG binds
// the currently accepted AES-GCM v2 nonce base to that sender.
type mediaReplayState struct {
	base    [12]byte
	known   bool
	highest uint32
	seen    uint64
}

// acceptMediaCounter updates only after AES-GCM authentication has succeeded.
// This prevents forged high counters from advancing the replay window.
func (s *relaySession) acceptMediaCounter(senderID uint32, base [12]byte, counter uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.mediaReplay[senderID]
	if !state.known || state.base != base {
		s.mediaReplay[senderID] = mediaReplayState{base: base, known: true, highest: counter, seen: 1}
		return true
	}
	if counter > state.highest {
		delta := counter - state.highest
		if delta >= 64 {
			state.seen = 1
		} else {
			state.seen = state.seen<<delta | 1
		}
		state.highest = counter
		s.mediaReplay[senderID] = state
		return true
	}
	delta := state.highest - counter
	if delta >= 64 || state.seen&(uint64(1)<<delta) != 0 {
		return false
	}
	state.seen |= uint64(1) << delta
	s.mediaReplay[senderID] = state
	return true
}
