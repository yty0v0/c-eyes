package imagebackend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	containerd "github.com/containerd/containerd"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type dockerBackend struct {
	ctx context.Context
}

func (b dockerBackend) Name() string { return "docker" }

func (b dockerBackend) LoadImage(imageRef string) (v1.Image, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse image reference failed: %w", err)
	}
	return daemon.Image(ref, daemon.WithContext(b.ctx))
}

type podmanBackend struct {
	ctx context.Context
}

func (b podmanBackend) Name() string { return "podman" }

func (b podmanBackend) LoadImage(imageRef string) (v1.Image, error) {
	socketPath, err := resolvePodmanSocketPath()
	if err != nil {
		return nil, err
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(b.ctx, "unix", socketPath)
			},
		},
	}
	inspectURL := fmt.Sprintf("http://podman/images/%s/json", imageRef)
	inspectReq, err := http.NewRequestWithContext(b.ctx, http.MethodGet, inspectURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	inspectResp, err := client.Do(inspectReq)
	if err != nil {
		return nil, err
	}
	_ = inspectResp.Body.Close()
	if inspectResp.StatusCode < 200 || inspectResp.StatusCode >= 300 {
		return nil, fmt.Errorf("podman image inspect failed: %s", inspectResp.Status)
	}

	exportURL := fmt.Sprintf("http://podman/images/%s/get", imageRef)
	exportReq, err := http.NewRequestWithContext(b.ctx, http.MethodGet, exportURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	exportResp, err := client.Do(exportReq)
	if err != nil {
		return nil, err
	}
	if exportResp.StatusCode < 200 || exportResp.StatusCode >= 300 {
		defer func() { _ = exportResp.Body.Close() }()
		return nil, fmt.Errorf("podman image export failed: %s", exportResp.Status)
	}
	body, err := io.ReadAll(exportResp.Body)
	_ = exportResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read podman image export failed: %w", err)
	}
	img, err := tarball.Image(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("load podman image export failed: %w", err)
	}
	return img, nil
}

type containerdBackend struct {
	ctx context.Context
}

func (b containerdBackend) Name() string { return "containerd" }

func (b containerdBackend) LoadImage(imageRef string) (v1.Image, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("containerd native backend is not supported on windows")
	}

	socketPath, err := resolveContainerdSocketPath()
	if err != nil {
		return nil, err
	}
	namespace := resolveContainerdNamespace()

	client, err := containerd.New(socketPath)
	if err != nil {
		return nil, fmt.Errorf("containerd client init failed: %w", err)
	}
	defer func() { _ = client.Close() }()

	ctx := namespaces.WithNamespace(b.ctx, namespace)
	img, err := client.GetImage(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("containerd image lookup failed for namespace %q: %w", namespace, err)
	}

	var exportBuf bytes.Buffer
	if err := client.Export(ctx, &exportBuf, archive.WithImage(client.ImageService(), img.Name())); err != nil {
		return nil, fmt.Errorf("containerd image export failed: %w", err)
	}
	var archiveRef *name.Tag
	tag, err := name.NewTag(img.Name())
	if err == nil {
		archiveRef = &tag
	}
	tarImg, err := tarball.Image(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(exportBuf.Bytes())), nil
	}, archiveRef)
	if err != nil {
		return nil, fmt.Errorf("containerd exported image load failed: %w", err)
	}
	return tarImg, nil
}

func DefaultBackends(ctx context.Context) []ImageBackend {
	return []ImageBackend{
		dockerBackend{ctx: ctx},
		podmanBackend{ctx: ctx},
		containerdBackend{ctx: ctx},
	}
}

func resolvePodmanSocketPath() (string, error) {
	if runtime.GOOS == "windows" {
		return "", errors.New("podman native socket unavailable on windows")
	}
	if host := strings.TrimSpace(os.Getenv("PODMAN_HOST")); host != "" {
		if strings.HasPrefix(host, "unix://") {
			socketPath := strings.TrimPrefix(host, "unix://")
			if _, err := os.Stat(socketPath); err == nil {
				return socketPath, nil
			}
			return "", fmt.Errorf("podman socket not found: %s", socketPath)
		}
		return "", fmt.Errorf("unsupported podman host scheme: %s", host)
	}
	runtimeDir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR"))
	if runtimeDir == "" {
		return "", errors.New("XDG_RUNTIME_DIR is not set for podman socket discovery")
	}
	socketPath := filepath.Join(runtimeDir, "podman", "podman.sock")
	if _, err := os.Stat(socketPath); err != nil {
		return "", fmt.Errorf("podman socket not found: %s", socketPath)
	}
	return socketPath, nil
}

func resolveContainerdSocketPath() (string, error) {
	if host := strings.TrimSpace(os.Getenv("CONTAINERD_ADDRESS")); host != "" {
		if _, err := os.Stat(host); err == nil {
			return host, nil
		}
		return "", fmt.Errorf("containerd socket not found: %s", host)
	}

	socketPath := "/run/containerd/containerd.sock"
	if _, err := os.Stat(socketPath); err != nil {
		return "", fmt.Errorf("containerd socket not found: %s", socketPath)
	}
	return socketPath, nil
}

func resolveContainerdNamespace() string {
	if ns := strings.TrimSpace(os.Getenv("CONTAINERD_NAMESPACE")); ns != "" {
		return ns
	}
	return "default"
}
