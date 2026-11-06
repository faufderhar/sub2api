//go:build race

package service

// raceDetectorEnabled reports whether tests run under -race (L-12): allocation-count
// assertions are skipped there because the race runtime instruments allocations.
const raceDetectorEnabled = true
