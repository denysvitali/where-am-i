package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"
	"github.com/spf13/viper"
)

// TestConfigureViper_IgnoresCwdConfig verifies that a config.yaml in the
// current working directory is NOT picked up by the default search path.
// This prevents running where-am-i from inside another project (e.g. one
// with its own config.yaml) from silently shadowing the global config in
// $XDG_CONFIG_HOME/where-am-i/config.yaml.
func TestConfigureViper_IgnoresCwdConfig(t *testing.T) {
	tmpHome := t.TempDir()
	origXDG := xdg.ConfigHome
	xdg.ConfigHome = tmpHome
	t.Cleanup(func() { xdg.ConfigHome = origXDG })

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	// A foreign config.yaml in cwd — must NOT be loaded.
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "config.yaml"), []byte("server:\n  url: from-cwd\n"), 0o644); err != nil {
		t.Fatalf("write cwd config: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// The global config that must win.
	globalDir := filepath.Join(tmpHome, "where-am-i")
	if err := os.MkdirAll(globalDir, 0o755); err != nil {
		t.Fatalf("mkdir global: %v", err)
	}
	if err := os.WriteFile(filepath.Join(globalDir, "config.yaml"), []byte("server:\n  url: from-global\n"), 0o644); err != nil {
		t.Fatalf("write global config: %v", err)
	}

	v := viper.New()
	configureViper(v, "")
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("read config: %v", err)
	}
	if got := v.GetString("server.url"); got != "from-global" {
		t.Errorf("server.url = %q, want %q (global config should win over cwd)", got, "from-global")
	}
}
