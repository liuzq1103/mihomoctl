//go:build !linux

package main

import "errors"

// Non-Linux builds stay headless: render mode and tests work everywhere, the
// interactive console itself is Linux-only like the rest of mihomoctl.
type rawTerm struct{}

func enterRaw() (*rawTerm, error)  { return nil, errors.New("tui-requires-linux-terminal") }
func (t *rawTerm) restore()        {}
func termSize() (int, int)         { return 80, 24 }
func watchResize() <-chan struct{} { return nil }
