package main

import "syscall"

// diskStat — размер и свободное место файловой системы с данными (том /data).
func diskStat(p string) (total, free int64) {
	var st syscall.Statfs_t
	if syscall.Statfs(p, &st) != nil {
		return 0, 0
	}
	return int64(st.Blocks) * int64(st.Bsize), int64(st.Bavail) * int64(st.Bsize)
}
