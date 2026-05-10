package imagebackend

import v1 "github.com/google/go-containerregistry/pkg/v1"

type TargetMode string

const (
	TargetModePath         TargetMode = "path"
	TargetModeImage        TargetMode = "image"
	TargetModeImageArchive TargetMode = "image_archive"
	TargetModeOCILayout    TargetMode = "oci_layout"
)

type ResolveOptions struct {
	Path        string
	ImageTarget string
	TargetType  string
}

type ResolvedTarget struct {
	RootPath string
	Mode     TargetMode
	Cleanup  func()
}

type ImageBackend interface {
	Name() string
	LoadImage(imageRef string) (v1.Image, error)
}
