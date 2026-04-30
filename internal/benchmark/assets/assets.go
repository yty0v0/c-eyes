package assets

import "embed"

// Files contains packaged benchmark template scripts for all supported platforms.
//
//go:embed windows/* linux/* euleros/* kylin/*
var Files embed.FS
