package assets

import "embed"

// Files contains packaged non-script benchmark assets for all supported platforms.
//
//go:embed windows/*.yaml windows/*.txt linux/*.yaml euleros/*.yaml kylin/*.yaml
var Files embed.FS
