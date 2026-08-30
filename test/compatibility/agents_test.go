//go:build compat

package compatibility

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestAgentBinaryOfflineToolLaunch intentionally accepts only the exact
// installed Claude/Codex binary. A failed hermetic model/tool protocol is a
// producer failure; this test never replaces it with a wrapper or shim.
func TestAgentBinaryOfflineToolLaunch(t *testing.T) {
	agent := os.Getenv("KORDN_AGENT")
	if agent == "" {
		if os.Getenv("KORDN_EXTERNAL_REQUIRED") == "1" {
			t.Fatal("required external agent is unset")
		}
		t.Skip("set KORDN_AGENT to claude or codex in the external producer job")
	}
	key := "codex"
	if strings.EqualFold(agent, "claude") {
		key = "claude_code"
	}
	path := requirePinnedExecutable(t, key)
	run := newFixtureRun(t, "GetSessionToken")
	marker := filepath.Join(t.TempDir(), "agent-marker")
	script := filepath.Join(t.TempDir(), "agent-tool.sh")
	content := "#!/bin/sh\nif ! mkdir \"$KORDN_AGENT_MARKER.lock\" 2>/dev/null; then exit 0; fi\nprintf '%s\\n' child-started > \"$KORDN_AGENT_MARKER\"\naws sts get-caller-identity --endpoint-url \"$KORDN_FIXTURE_ENDPOINT\" >> \"$KORDN_AGENT_MARKER\"\n" +
		"curl --fail --silent --show-error \"$KORDN_AGENT_API_URL/opaque\" -o /dev/null\nprintf '%s\\n' child-finished >> \"$KORDN_AGENT_MARKER\"\n"
	if err := os.WriteFile(script, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}

	var modelCalls atomic.Int64
	model := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.EqualFold(agent, "claude") {
			if strings.Contains(r.URL.Path, "count_tokens") {
				_ = json.NewEncoder(w).Encode(map[string]int{"input_tokens": 1})
				return
			}
			var request struct {
				Model    string `json:"model"`
				Messages []struct {
					Content []struct {
						Type string `json:"type"`
					} `json:"content"`
				} `json:"messages"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "invalid fixture request", http.StatusBadRequest)
				return
			}
			hasToolResult := false
			for _, message := range request.Messages {
				for _, content := range message.Content {
					hasToolResult = hasToolResult || content.Type == "tool_result"
				}
			}
			response := map[string]any{
				"id": "msg_01KORDNCOMPATIBILITYFIXTURE", "type": "message", "role": "assistant", "model": request.Model,
				"stop_sequence": nil, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
			}
			if hasToolResult {
				response["content"] = []any{map[string]any{"type": "text", "text": "fixture complete"}}
				response["stop_reason"] = "end_turn"
			} else {
				response["content"] = []any{map[string]any{"type": "tool_use", "id": "toolu_01KORDNCOMPATIBILITYFIXTURE", "name": "Bash", "input": map[string]any{"command": script, "description": "Run compatibility fixture"}}}
				response["stop_reason"] = "tool_use"
			}
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		call := modelCalls.Add(1)
		if call == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "chatcmpl_fixture", "choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "call_fixture", "type": "function", "function": map[string]string{"name": "shell", "arguments": `{"command":"` + strings.ReplaceAll(script, `\`, `\\`) + `"}`}}}}}}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "chat_done", "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": "fixture complete"}}}})
	}))
	defer model.Close()
	modelCAPEM := writeTemp(t, "agent-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: model.Certificate().Raw})))
	env := append(os.Environ(), run.env...)
	// The agent API is a local non-AWS TLS endpoint. Remove the fixture's
	// loopback NO_PROXY exemption so the child must exercise Kordn's opaque
	// CONNECT relay, and give curl the same test-only trust root as the agent.
	env = append(env, "KORDN_AGENT_MARKER="+marker, "KORDN_FIXTURE_ENDPOINT="+run.endpoint(), "KORDN_AGENT_API_URL="+model.URL, "KORDN_AGENT_OFFLINE=1", "ANTHROPIC_API_KEY=fixture-key", "OPENAI_API_KEY=fixture-key", "NO_PROXY=", "no_proxy=", "CURL_CA_BUNDLE="+modelCAPEM, "NODE_EXTRA_CA_CERTS="+modelCAPEM)
	if strings.EqualFold(agent, "claude") {
		env = append(env, "ANTHROPIC_BASE_URL="+model.URL)
	} else {
		env = append(env, "OPENAI_BASE_URL="+model.URL+"/v1")
	}
	cmd := execAgent(t, path, agent, script)
	cmd.Env = env
	output, err := runOutput(t, cmd)
	if err != nil {
		t.Fatalf("exact %s offline invocation failed (unsupported producers must fail): %v\n%s", agent, err, output)
	}
	markerBytes, readErr := os.ReadFile(marker)
	if readErr != nil {
		t.Fatalf("agent did not launch returned tool command: %v\n%s", readErr, output)
	}
	if !strings.Contains(string(markerBytes), "child-started") || !strings.Contains(string(markerBytes), "child-finished") {
		t.Fatalf("child markers missing: %s", markerBytes)
	}
	run.assertLedger(t, "GetCallerIdentity", 1)
	run.assertAudit(t, "GetCallerIdentity", "allow")
}

func execAgent(t *testing.T, path, agent, script string) *exec.Cmd {
	t.Helper()
	if strings.EqualFold(agent, "claude") {
		// Print mode cannot answer permission prompts. This process runs inside
		// the isolated compatibility fixture, so bypass permissions explicitly
		// and place options before the prompt to ensure the pinned CLI parses them.
		return exec.Command(path, "--dangerously-skip-permissions", "--print", "Use the Bash tool to run "+script)
	}
	return exec.Command(path, "exec", "--full-auto", "Use the shell tool to run "+script)
}
