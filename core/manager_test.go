package core

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/mensylisir/helm-proxy/config"
)

func TestNewManager(t *testing.T) {
	cfg := &config.Config{
		Helm: config.HelmConfig{
			Driver:  "secret",
			RepoMap: map[string]string{"myrepo": "http://test.repo"},
		},
	}
	logger := zap.NewNop()

	manager := NewManager(cfg, logger)

	if manager == nil {
		t.Fatal("NewManager returned nil")
	}

	if manager.cfg != cfg {
		t.Error("Manager config not set correctly")
	}

	if manager.logger != logger {
		t.Error("Manager logger not set correctly")
	}

	if manager.chartCache == nil {
		t.Error("Chart cache not initialized")
	}

	if manager.keyLock == nil {
		t.Error("KeyLock not initialized")
	}
}

func TestChartCache(t *testing.T) {
	cache := NewChartCache(100, 60)

	// Test initial state
	if entry, exists := cache.Get("nonexistent"); exists {
		t.Errorf("Cache should be empty initially, got entry: %v", entry)
	}

	// Test Set and Get
	entry := &ChartEntry{
		ChartPath:   "/test/chart",
		DownloadedAt: time.Now(),
		Version:     "1.0.0",
		ChartName:   "test-chart",
	}
	cache.Set("test-key", entry)

	retrieved, exists := cache.Get("test-key")
	if !exists {
		t.Error("Cache should return true for existing key")
	}
	if retrieved.ChartPath != "/test/chart" {
		t.Error("Cache returned wrong chart path")
	}

	// Test Clear
	cache.Clear()
	if entry, exists := cache.Get("test-key"); exists {
		t.Errorf("Cache should be empty after Clear, got entry: %v", entry)
	}
}

func TestResolveChart(t *testing.T) {
	cfg := &config.Config{
		Helm: config.HelmConfig{
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
				"stable": "https://charts.helm.sh/stable",
			},
		},
	}
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	tests := []struct {
		name      string
		externalID string
		wantURL   string
		wantVer   string
		wantErr   bool
	}{
		{
			name:      "myrepo podinfo",
			externalID: "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
			wantURL:   "http://registry.dev.rdev.tech:18091/repository/helm/podinfo-6.5.4.tgz",
			wantVer:   "6.5.4",
			wantErr:   false,
		},
		{
			name:      "stable nginx",
			externalID: "catalog://?catalog=stable&template=nginx&version=1.0.0",
			wantURL:   "https://charts.helm.sh/stable/charts/nginx-1.0.0.tgz",
			wantVer:   "1.0.0",
			wantErr:   false,
		},
		{
			name:      "unknown catalog",
			externalID: "catalog://?catalog=unknown&template=test&version=1.0.0",
			wantURL:   "",
			wantVer:   "",
			wantErr:   true,
		},
		{
			name:      "missing version",
			externalID: "catalog://?catalog=myrepo&template=podinfo",
			wantURL:   "http://registry.dev.rdev.tech:18091/repository/helm/podinfo",
			wantVer:   "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chartURL, version, err := manager.resolveChart(tt.externalID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("resolveChart() error = nil, wantErr %v", tt.wantErr)
					return
				}
			} else {
				if err != nil {
					t.Errorf("resolveChart() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if chartURL != tt.wantURL {
					t.Errorf("resolveChart() chartURL = %v, want %v", chartURL, tt.wantURL)
				}
				if version != tt.wantVer {
					t.Errorf("resolveChart() version = %v, want %v", version, tt.wantVer)
				}
			}
		})
	}
}

func TestExtractChartName(t *testing.T) {
	cfg := &config.Config{
		Helm: config.HelmConfig{
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
			},
		},
	}
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	tests := []struct {
		name      string
		externalID string
		want      string
	}{
		{
			name:      "podinfo chart",
			externalID: "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
			want:      "podinfo",
		},
		{
			name:      "nginx chart",
			externalID: "catalog://?catalog=stable&template=nginx",
			want:      "nginx",
		},
		{
			name:      "invalid format",
			externalID: "invalid",
			want:      "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := manager.extractChartName(tt.externalID)
			if got != tt.want {
				t.Errorf("extractChartName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseValues(t *testing.T) {
	cfg := &config.Config{}
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	tests := []struct {
		name      string
		answers   map[string]string
		valuesYaml string
		wantErr   bool
	}{
		{
			name: "simple answers",
			answers: map[string]string{
				"service.nodePort": "31130",
				"image.tag":       "6.5.4",
			},
			valuesYaml: "",
			wantErr:   false,
		},
		{
			name: "auto-inference nodePort",
			answers: map[string]string{
				"service.nodePort": "31130",
			},
			valuesYaml: "",
			wantErr: false,
		},
		{
			name: "values yaml",
			answers: map[string]string{},
			valuesYaml: "image:\n  tag: \"6.5.4\"\nservice:\n  type: NodePort\n  nodePort: 31130\nreplicaCount: 2\n",
			wantErr: false,
		},
		{
			name: "mixed answers and yaml",
			answers: map[string]string{
				"service.nodePort": "31130",
			},
			valuesYaml: "image:\n  tag: \"6.5.4\"\nservice:\n  type: NodePort\nreplicaCount: 2\n",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := manager.ParseValues(tt.answers, tt.valuesYaml)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseValues() error = nil, wantErr %v", tt.wantErr)
					return
				}
			} else {
				if err != nil {
					t.Errorf("ParseValues() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if got == nil {
					t.Error("ParseValues() returned nil")
					return
				}
			}
		})
	}
}

func TestMapHelmStateToRancher(t *testing.T) {
	// Note: This test would require creating mock release.Release objects
	// In a real implementation, we would use the release package from Helm
	// For now, we'll skip detailed state mapping tests
}

func TestGetActionConfig(t *testing.T) {
	cfg := &config.Config{
		Helm: config.HelmConfig{
			Driver: "secret",
		},
	}
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	// Test getting action config for a namespace
	actionConfig, err := manager.getActionConfig("default")
	if err != nil {
		t.Errorf("getActionConfig() error = %v", err)
		return
	}
	if actionConfig == nil {
		t.Error("getActionConfig() returned nil")
	}
}
