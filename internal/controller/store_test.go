package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/define42/HCOS/internal/protocol"
)

func TestStorePermissionsAndCorruption(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	target := protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1"}
	if err := store.PutDesired(ctx, "compute-01", target); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		root,
		filepath.Join(root, "desired"),
		filepath.Join(root, "reports"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0700 {
			t.Fatalf("%s mode = %04o, want 0700", path, info.Mode().Perm())
		}
	}
	path := filepath.Join(root, "desired", "compute-01.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("desired file mode = %04o, want 0600", info.Mode().Perm())
	}
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Desired(ctx, "compute-01"); err == nil {
		t.Fatal("corrupted stored desired state was accepted")
	}
}

func TestStoreRejectsTraversalAndUnavailableDirectory(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := store.Desired(ctx, "../other"); err == nil {
		t.Fatal("path traversal node ID was accepted")
	}
	if err := store.PutReport(ctx, "../other", protocol.Report{}); err == nil {
		t.Fatal("path traversal report was accepted")
	}
	if err := os.Remove(filepath.Join(store.root, "reports")); err != nil {
		t.Fatal(err)
	}
	if err := store.Ready(ctx); err == nil {
		t.Fatal("missing store directory was reported ready")
	}
}

func TestStoreContextCancellation(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Desired(ctx, "compute-01"); err == nil {
		t.Fatal("canceled desired read succeeded")
	}
	if err := store.PutDesired(ctx, "compute-01", protocol.DesiredState{
		APIVersion: protocol.APIVersion,
		Revision:   "1",
	}); err == nil {
		t.Fatal("canceled desired write succeeded")
	}
}

func TestOpenStoreDoesNotChangeExistingDirectoryMode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(root); err == nil {
		t.Fatal("public existing store directory was accepted")
	}
	after, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("store changed existing directory mode from %04o to %04o", before.Mode().Perm(), after.Mode().Perm())
	}
}
