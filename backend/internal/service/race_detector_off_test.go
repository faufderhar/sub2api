//go:build !race

package service

// raceDetectorEnabled reports whether tests run under -race (L-12).
const raceDetectorEnabled = false
