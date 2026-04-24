package filescan

import (
	"errors"
	"os"
	"testing"
)

func TestIsPermissionDeniedError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "os permission", err: os.ErrPermission, want: true},
		{name: "wrapped permission", err: errors.New("open C:\\secret.txt: Access is denied."), want: true},
		{name: "unix permission", err: errors.New("open /root/secret: permission denied"), want: true},
		{name: "unrelated", err: errors.New("file not found"), want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isPermissionDeniedError(tc.err); got != tc.want {
				t.Fatalf("unexpected result: got=%v want=%v err=%v", got, tc.want, tc.err)
			}
		})
	}
}
