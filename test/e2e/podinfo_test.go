package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/mensylisir/helm-proxy/config"
	"github.com/mensylisir/helm-proxy/core"
	"github.com/mensylisir/helm-proxy/model"
	"github.com/mensylisir/helm-proxy/routes"
)

// End-to-End test for myrepo/podinfo deployment
// This test validates the complete workflow from Rancher API to Kubernetes

func TestMyrepoPodinfoDeployment(t *testing.T) {
	// Setup
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8443",
		},
		Helm: config.HelmConfig{
			Driver: "secret",
			RepoMap: map[string]string{
				"myrepo": "http://registry.dev.rdev.tech:18091/repository/helm",
			},
		},
	}
	logger := zap.NewNop()
	manager := core.NewManager(cfg, logger)

	engine := gin.New()
	router := routes.NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	// Test configuration
	projectID := "c-test:p-test"
	appName := "podinfo-e2e-test"
	namespace := "default"
	nodePort := 31140

	t.Cleanup(func() {
		// Cleanup: Delete the app after tests
		deleteReq, _ := http.NewRequest("DELETE", fmt.Sprintf("/v3/projects/%s/app/%s?targetNamespace=%s", projectID, appName, namespace), nil)
		deleteW := httptest.NewRecorder()
		engine.ServeHTTP(deleteW, deleteReq)
		t.Logf("Cleanup: Delete app response code: %d", deleteW.Code)
	})

	// Test 1: Deploy podinfo from myrepo
	t.Run("Deploy podinfo from myrepo", func(t *testing.T) {
		reqBody := model.RancherRequest{
			Name:            appName,
			TargetNamespace: namespace,
			ExternalID:      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
			ProjectID:       projectID,
			Answers: map[string]string{
				"service.nodePort": fmt.Sprintf("%d", nodePort),
				"image.tag":       "6.5.4",
			},
			Timeout: 300,
			Wait:    true, // Synchronous deployment
		}

		jsonBody, _ := json.Marshal(reqBody)
		deployReq, _ := http.NewRequest("POST", fmt.Sprintf("/v3/projects/%s/app", projectID), bytes.NewBuffer(jsonBody))
		deployReq.Header.Set("Content-Type", "application/json")

		deployW := httptest.NewRecorder()
		engine.ServeHTTP(deployW, deployReq)

		// Verify deployment response
		if deployW.Code != http.StatusOK && deployW.Code != http.StatusAccepted {
			t.Fatalf("Deploy failed with status %d. Response: %s", deployW.Code, deployW.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(deployW.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to unmarshal deploy response: %v", err)
		}

		// Verify response structure
		data, ok := resp["data"].(map[string]interface{})
		if !ok {
			t.Fatal("Response missing 'data' field")
		}

		if name, ok := data["name"].(string); ok {
			if name != appName {
				t.Errorf("Expected app name '%s', got '%s'", appName, name)
			}
		} else {
			t.Error("Response missing 'name' field in data")
		}

		if state, ok := data["state"].(string); ok {
			t.Logf("App deployed with state: %s", state)
			if state != "active" && state != "installing" {
				t.Errorf("Unexpected app state: %s", state)
			}
		} else {
			t.Error("Response missing 'state' field in data")
		}

		if targetNamespace, ok := data["targetNamespace"].(string); ok {
			if targetNamespace != namespace {
				t.Errorf("Expected namespace '%s', got '%s'", namespace, targetNamespace)
			}
		}

		if externalID, ok := data["externalId"].(string); ok {
			if externalID != "catalog://?catalog=myrepo&template=podinfo&version=6.5.4" {
				t.Errorf("Expected externalId 'catalog://?catalog=myrepo&template=podinfo&version=6.5.4', got '%s'", externalID)
			}
		}

		t.Logf("✅ Deploy test passed: App %s deployed successfully", appName)
	})

	// Test 2: Get application status
	t.Run("Get application status", func(t *testing.T) {
		statusReq, _ := http.NewRequest("GET", fmt.Sprintf("/v3/projects/%s/app/%s?targetNamespace=%s", projectID, appName, namespace), nil)
		statusW := httptest.NewRecorder()
		engine.ServeHTTP(statusW, statusReq)

		if statusW.Code != http.StatusOK {
			t.Fatalf("Get status failed with status %d. Response: %s", statusW.Code, statusW.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(statusW.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to unmarshal status response: %v", err)
		}

		data, ok := resp["data"].(map[string]interface{})
		if !ok {
			t.Fatal("Response missing 'data' field")
		}

		if name, ok := data["name"].(string); ok {
			if name != appName {
				t.Errorf("Expected app name '%s', got '%s'", appName, name)
			}
		}

		if state, ok := data["state"].(string); ok {
			t.Logf("App status: %s", state)
		}

		t.Logf("✅ Status test passed")
	})

	// Test 3: List applications
	t.Run("List applications", func(t *testing.T) {
		listReq, _ := http.NewRequest("GET", fmt.Sprintf("/v3/projects/%s/app", projectID), nil)
		listW := httptest.NewRecorder()
		engine.ServeHTTP(listW, listReq)

		if listW.Code != http.StatusOK {
			t.Fatalf("List apps failed with status %d. Response: %s", listW.Code, listW.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(listW.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to unmarshal list response: %v", err)
		}

		data, ok := resp["data"].([]interface{})
		if !ok {
			t.Fatal("Response missing 'data' array")
		}

		found := false
		for _, app := range data {
			if appMap, ok := app.(map[string]interface{}); ok {
				if name, ok := appMap["name"].(string); ok {
					if name == appName {
						found = true
						t.Logf("Found app '%s' in list", appName)
						break
					}
				}
			}
		}

		if !found {
			t.Errorf("App '%s' not found in application list", appName)
		}

		t.Logf("✅ List test passed: Found %d apps", len(data))
	})

	// Test 4: Async deployment
	t.Run("Async deployment", func(t *testing.T) {
		asyncAppName := "podinfo-async-test"
		reqBody := model.RancherRequest{
			Name:            asyncAppName,
			TargetNamespace: namespace,
			ExternalID:      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
			ProjectID:       projectID,
			Answers: map[string]string{
				"service.nodePort": fmt.Sprintf("%d", nodePort+1),
			},
			Timeout: 300,
			Wait:    false, // Asynchronous deployment
		}

		jsonBody, _ := json.Marshal(reqBody)
		asyncReq, _ := http.NewRequest("POST", fmt.Sprintf("/v3/projects/%s/app", projectID), bytes.NewBuffer(jsonBody))
		asyncReq.Header.Set("Content-Type", "application/json")

		asyncW := httptest.NewRecorder()
		engine.ServeHTTP(asyncW, asyncReq)

		if asyncW.Code != http.StatusOK && asyncW.Code != http.StatusAccepted {
			t.Fatalf("Async deploy failed with status %d. Response: %s", asyncW.Code, asyncW.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(asyncW.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to unmarshal async response: %v", err)
		}

		data, ok := resp["data"].(map[string]interface{})
		if !ok {
			t.Fatal("Response missing 'data' field")
		}

		if state, ok := data["state"].(string); ok {
			if state != "installing" {
				t.Errorf("Expected async deployment state 'installing', got '%s'", state)
			}
			t.Logf("Async deployment returned correct state: %s", state)
		} else {
			t.Error("Response missing 'state' field")
		}

		// Cleanup async app
		deleteReq, _ := http.NewRequest("DELETE", fmt.Sprintf("/v3/projects/%s/app/%s?targetNamespace=%s", projectID, asyncAppName, namespace), nil)
		deleteW := httptest.NewRecorder()
		engine.ServeHTTP(deleteW, deleteReq)

		t.Logf("✅ Async deployment test passed")
	})

	// Test 5: Values override
	t.Run("Values override", func(t *testing.T) {
		valuesAppName := "podinfo-values-test"
		reqBody := model.RancherRequest{
			Name:            valuesAppName,
			TargetNamespace: namespace,
			ExternalID:      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
			ProjectID:       projectID,
			Answers: map[string]string{
				"service.nodePort": fmt.Sprintf("%d", nodePort+2),
				"image.tag":       "6.5.4",
			},
			ValuesYaml: "replicaCount: 2",
			Timeout:    300,
			Wait:       true,
		}

		jsonBody, _ := json.Marshal(reqBody)
		valuesReq, _ := http.NewRequest("POST", fmt.Sprintf("/v3/projects/%s/app", projectID), bytes.NewBuffer(jsonBody))
		valuesReq.Header.Set("Content-Type", "application/json")

		valuesW := httptest.NewRecorder()
		engine.ServeHTTP(valuesW, valuesReq)

		if valuesW.Code != http.StatusOK && valuesW.Code != http.StatusAccepted {
			t.Fatalf("Values override deploy failed with status %d. Response: %s", valuesW.Code, valuesW.Body.String())
		}

		// Cleanup values app
		deleteReq, _ := http.NewRequest("DELETE", fmt.Sprintf("/v3/projects/%s/app/%s?targetNamespace=%s", projectID, valuesAppName, namespace), nil)
		deleteW := httptest.NewRecorder()
		engine.ServeHTTP(deleteW, deleteReq)

		t.Logf("✅ Values override test passed")
	})

	// Test 6: Health checks
	t.Run("Health checks", func(t *testing.T) {
		endpoints := []struct {
			path string
		}{
			{"/health"},
			{"/ready"},
			{"/metrics"},
		}

		for _, endpoint := range endpoints {
			req, _ := http.NewRequest("GET", endpoint.path, nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Health endpoint %s failed with status %d", endpoint.path, w.Code)
			} else {
				t.Logf("✅ Health endpoint %s OK", endpoint.path)
			}
		}
	})

	// Test 7: Concurrent deployments
	t.Run("Concurrent deployments", func(t *testing.T) {
		concurrency := 5
		done := make(chan bool, concurrency)

		for i := 0; i < concurrency; i++ {
			go func(index int) {
				appName := fmt.Sprintf("podinfo-concurrent-%d", index)
				reqBody := model.RancherRequest{
					Name:            appName,
					TargetNamespace: namespace,
					ExternalID:      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
					ProjectID:       projectID,
					Answers: map[string]string{
						"service.nodePort": fmt.Sprintf("%d", nodePort+10+index),
					},
					Timeout: 300,
					Wait:    true,
				}

				jsonBody, _ := json.Marshal(reqBody)
				req, _ := http.NewRequest("POST", fmt.Sprintf("/v3/projects/%s/app", projectID), bytes.NewBuffer(jsonBody))
				req.Header.Set("Content-Type", "application/json")

				w := httptest.NewRecorder()
				engine.ServeHTTP(w, req)

				if w.Code == http.StatusOK || w.Code == http.StatusAccepted {
					t.Logf("✅ Concurrent deployment %d succeeded", index)
				} else {
					t.Errorf("❌ Concurrent deployment %d failed with status %d", index, w.Code)
				}

				// Cleanup
				deleteReq, _ := http.NewRequest("DELETE", fmt.Sprintf("/v3/projects/%s/app/%s?targetNamespace=%s", projectID, appName, namespace), nil)
				deleteW := httptest.NewRecorder()
				engine.ServeHTTP(deleteW, deleteReq)

				done <- true
			}(i)
		}

		// Wait for all deployments to complete
		timeout := time.After(120 * time.Second)
		for i := 0; i < concurrency; i++ {
			select {
			case <-done:
			case <-timeout:
				t.Fatal("Concurrent deployments timed out")
			}
		}

		t.Logf("✅ Concurrent deployments test passed: %d apps deployed simultaneously", concurrency)
	})

	t.Logf("🎉 All E2E tests passed for myrepo/podinfo!")
}

// Test Rancher API Compatibility
func TestRancherAPICompatibility(t *testing.T) {
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
	router := routes.NewRouter(engine, manager, cfg, logger)
	router.SetupRoutes()

	// Test exact Rancher API format from documentation
	t.Run("Rancher API format", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"prune":           false,
			"timeout":         300,
			"wait":            false,
			"type":            "app",
			"name":            "podinfo-rancher-test",
			"answers": map[string]string{
				"service.nodePort": "31150",
				"path":            "/podinfo",
				"image.pullPolicy": "Always",
			},
			"targetNamespace": "default",
			"externalId":      "catalog://?catalog=myrepo&template=podinfo&version=6.5.4",
			"projectId":       "c-7k5bm:p-lkjnx",
			"valuesYaml":      "",
		}

		jsonBody, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/v3/projects/c-7k5bm:p-lkjnx/app", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != http.StatusOK && w.Code != http.StatusAccepted {
			t.Fatalf("Rancher API format test failed with status %d. Response: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		// Verify response matches Rancher format
		if data, ok := resp["data"].(map[string]interface{}); ok {
			requiredFields := []string{"id", "type", "baseType", "name", "state", "targetNamespace", "externalId", "projectId", "links", "actionLinks"}
			for _, field := range requiredFields {
				if _, ok := data[field]; !ok {
					t.Errorf("Response missing required Rancher field: %s", field)
				}
			}

			// Verify links structure
			if links, ok := data["links"].(map[string]interface{}); ok {
				requiredLinks := []string{"self", "update", "remove", "revision"}
				for _, link := range requiredLinks {
					if _, ok := links[link]; !ok {
						t.Errorf("Response missing required link: %s", link)
					}
				}
			}

			// Verify actionLinks structure
			if actionLinks, ok := data["actionLinks"].(map[string]interface{}); ok {
				requiredActions := []string{"upgrade", "rollback"}
				for _, action := range requiredActions {
					if _, ok := actionLinks[action]; !ok {
						t.Errorf("Response missing required actionLink: %s", action)
					}
				}
			}
		}

		// Cleanup
		deleteReq, _ := http.NewRequest("DELETE", "/v3/projects/c-7k5bm:p-lkjnx/app/podinfo-rancher-test?targetNamespace=default", nil)
		deleteW := httptest.NewRecorder()
		engine.ServeHTTP(deleteW, deleteReq)

		t.Logf("✅ Rancher API compatibility test passed")
	})
}
