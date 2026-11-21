//go:build !linux

package main

func diskStat(p string) (total, free int64) { return 0, 0 }
