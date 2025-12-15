package routes

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/mensylisir/helm-proxy/config"
	"github.com/mensylisir/helm-proxy/core"
	"github.com/mensylisir/helm-proxy/model"
)

func TestSetupRoutes(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8443",
		},
		Helm: config.HelmConfig{
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
			},
		},
	}
	logger := zap.NewNop()
	manager := core.NewManager(cfg, logger)

	engine := gin.New()
	router := NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	if engine == nil {
		t.Fatal("SetupRoutes() failed to create router")
	}
}

func TestDeployApp(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8443",
		},
		Helm: config.HelmConfig{
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
			},
		},
	}
	logger := zap.NewNop()
	manager := core.NewManager(cfg, logger)

	engine := gin.New()
	router := NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	// Create test request
	reqBody := model.RancherRequest{
		Name:            "test-app",
		TargetNamespace: "default",
		ExternalID:      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
		ProjectID:       "c-test:p-test",
		Answers: map[string]string{
			"service.nodePort": "31130",
		},
		Timeout: 300,
		Wait:    true,
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/v3/projects/c-test:p-test/app", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Check status code
	if w.Code != http.StatusOK && w.Code != http.StatusAccepted {
		t.Errorf("Expected status %d or %d, got %d", http.StatusOK, http.StatusAccepted, w.Code)
		t.Logf("Response body: %s", w.Body.String())
	}

	// Check response structure
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	// Verify response has expected fields
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if name, ok := data["name"].(string); ok {
			if name != "test-app" {
				t.Errorf("Expected name 'test-app', got '%s'", name)
			}
		}
	}
}

func TestGetAppStatus(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8443",
		},
		Helm: config.HelmConfig{
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
			},
		},
	}
	logger := zap.NewNop()
	manager := core.NewManager(cfg, logger)

	engine := gin.New()
	router := NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	// First deploy an app
	reqBody := model.RancherRequest{
		Name:            "test-status-app",
		TargetNamespace: "default",
		ExternalID:      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
		ProjectID:       "c-test:p-test",
		Answers: map[string]string{
			"service.nodePort": "31131",
		},
		Timeout: 300,
		Wait:    true,
	}

	jsonBody, _ := json.Marshal(reqBody)
	deployReq, _ := http.NewRequest("POST", "/v3/projects/c-test:p-test/app", bytes.NewBuffer(jsonBody))
	deployReq.Header.Set("Content-Type", "application/json")
	deployW := httptest.NewRecorder()
	engine.ServeHTTP(deployW, deployReq)

	// Now get the status
	statusReq, _ := http.NewRequest("GET", "/v3/projects/c-test:p-test/app/test-status-app", nil)
	statusW := httptest.NewRecorder()
	engine.ServeHTTP(statusW, statusReq)

	if statusW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, statusW.Code)
		t.Logf("Response body: %s", statusW.Body.String())
	}

	// Check response structure
	var resp map[string]interface{}
	if err := json.Unmarshal(statusW.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}
}

func TestListApps(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8443",
		},
		Helm: config.HelmConfig{
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
			},
		},
	}
	logger := zap.NewNop()
	manager := core.NewManager(cfg, logger)

	engine := gin.New()
	router := NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	req, _ := http.NewRequest("GET", "/v3/projects/c-test:p-test/app", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Check response structure
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	// Should have data field with array
	if data, ok := resp["data"]; ok {
		if arr, ok := data.([]interface{}); ok {
			t.Logf("Found %d apps in list", len(arr))
		}
	}
}

func TestDeleteApp(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8443",
		},
		Helm: config.HelmConfig{
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
			},
		},
	}
	logger := zap.NewNop()
	manager := core.NewManager(cfg, logger)

	engine := gin.New()
	router := NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	// First deploy an app to delete
	reqBody := model.RancherRequest{
		Name:            "test-delete-app",
		TargetNamespace: "default",
		ExternalID:      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
		ProjectID:       "c-test:p-test",
		Answers: map[string]string{
			"service.nodePort": "31132",
		},
		Timeout: 300,
		Wait:    true,
	}

	jsonBody, _ := json.Marshal(reqBody)
	deployReq, _ := http.NewRequest("POST", "/v3/projects/c-test:p-test/app", bytes.NewBuffer(jsonBody))
	deployReq.Header.Set("Content-Type", "application/json")
	deployW := httptest.NewRecorder()
	engine.ServeHTTP(deployW, deployReq)

	// Now delete the app
	deleteReq, _ := http.NewRequest("DELETE", "/v3/projects/c-test:p-test/app/test-delete-app?targetNamespace=default", nil)
	deleteW := httptest.NewRecorder()
	engine.ServeHTTP(deleteW, deleteReq)

	if deleteW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, deleteW.Code)
		t.Logf("Response body: %s", deleteW.Body.String())
	}

	// Check response structure
	var resp map[string]interface{}
	if err := json.Unmarshal(deleteW.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	// Verify response has expected fields
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if state, ok := data["state"].(string); ok {
			if state != "removing" {
				t.Errorf("Expected state 'removing', got '%s'", state)
			}
		}
	}
}

func TestUpgradeApp(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8443",
		},
		Helm: config.HelmConfig{
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
			},
		},
	}
	logger := zap.NewNop()
	manager := core.NewManager(cfg, logger)

	engine := gin.New()
	router := NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	// First deploy an app to upgrade
	reqBody := model.RancherRequest{
		Name:            "test-upgrade-app",
		TargetNamespace: "default",
		ExternalID:      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
		ProjectID:       "c-test:p-test",
		Answers: map[string]string{
			"service.nodePort": "31133",
		},
		Timeout: 300,
		Wait:    true,
	}

	jsonBody, _ := json.Marshal(reqBody)
	deployReq, _ := http.NewRequest("POST", "/v3/projects/c-test:p-test/app", bytes.NewBuffer(jsonBody))
	deployReq.Header.Set("Content-Type", "application/json")
	deployW := httptest.NewRecorder()
	engine.ServeHTTP(deployW, deployReq)

	// Now upgrade the app
	upgradeReqBody := map[string]interface{}{
		"externalId": "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
		"answers": map[string]string{
			"service.nodePort": "31133",
			"image.tag":       "6.5.4",
		},
	}
	upgradeJSON, _ := json.Marshal(upgradeReqBody)
	upgradeReq, _ := http.NewRequest("POST", "/v3/projects/c-test:p-test/app/test-upgrade-app?action=upgrade&targetNamespace=default", bytes.NewBuffer(upgradeJSON))
	upgradeReq.Header.Set("Content-Type", "application/json")
	upgradeW := httptest.NewRecorder()
	engine.ServeHTTP(upgradeW, upgradeReq)

	if upgradeW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, upgradeW.Code)
		t.Logf("Response body: %s", upgradeW.Body.String())
	}
}

func TestRollbackApp(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8443",
		},
		Helm: config.HelmConfig{
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
			},
		},
	}
	logger := zap.NewNop()
	manager := core.NewManager(cfg, logger)

	engine := gin.New()
	router := NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	// First deploy an app to rollback
	reqBody := model.RancherRequest{
		Name:            "test-rollback-app",
		TargetNamespace: "default",
		ExternalID:      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
		ProjectID:       "c-test:p-test",
		Answers: map[string]string{
			"service.nodePort": "31134",
		},
		Timeout: 300,
		Wait:    true,
	}

	jsonBody, _ := json.Marshal(reqBody)
	deployReq, _ := http.NewRequest("POST", "/v3/projects/c-test:p-test/app", bytes.NewBuffer(jsonBody))
	deployReq.Header.Set("Content-Type", "application/json")
	deployW := httptest.NewRecorder()
	engine.ServeHTTP(deployW, deployReq)

	// Now rollback the app
	rollbackReqBody := map[string]interface{}{
		"revision": 1,
	}
	rollbackJSON, _ := json.Marshal(rollbackReqBody)
	rollbackReq, _ := http.NewRequest("POST", "/v3/projects/c-test:p-test/app/test-rollback-app?action=rollback&targetNamespace=default", bytes.NewBuffer(rollbackJSON))
	rollbackReq.Header.Set("Content-Type", "application/json")
	rollbackW := httptest.NewRecorder()
	engine.ServeHTTP(rollbackW, rollbackReq)

	if rollbackW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rollbackW.Code)
		t.Logf("Response body: %s", rollbackW.Body.String())
	}
}

func TestHealthEndpoints(t *testing.T) {
	cfg := &config.Config{}
	logger := zap.NewNop()
	manager := core.NewManager(cfg, logger)

	engine := gin.New()
	router := NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	tests := []struct {
		path string
		code int
	}{
		{"/health", http.StatusOK},
		{"/ready", http.StatusOK},
		{"/metrics", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Code != tt.code {
				t.Errorf("Expected status %d, got %d", tt.code, w.Code)
			}
		})
	}
}
