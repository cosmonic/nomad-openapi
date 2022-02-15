package v1

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/hashicorp/nomad/command/agent"
	"github.com/hashicorp/nomad/testutil"
	"github.com/stretchr/testify/require"
)

var queryOpts = DefaultQueryOpts().
	WithAllowStale(true).
	WithWaitIndex(1000).
	WithWaitTime(100 * time.Second)

var writeOpts = DefaultWriteOpts()

// makeHTTPServer returns a test server whose logs will be written to
// the passed writer. If the writer is nil, the logs are written to stderr.
func makeHTTPServer(t testing.TB, cb func(c *agent.Config)) *agent.TestAgent {
	return agent.NewTestAgent(t, t.Name(), cb)
}

func httpTest(t testing.TB, cb func(c *agent.Config), f func(srv *agent.TestAgent)) {
	s := makeHTTPServer(t, cb)
	defer s.Shutdown()
	testutil.WaitForLeader(t, s.Agent.RPC)
	f(s)
}

func NewTestClient(testAgent *agent.TestAgent) (*Client, error) {
	os.Setenv("NOMAD_ADDR", fmt.Sprintf("http://%s:%d", testAgent.Config.BindAddr, testAgent.Config.Ports.HTTP))
	defer os.Setenv("NOMAD_ADDR", "http://127.0.0.1:4646")

	return NewClient()
}

func TestSetQueryOptions(t *testing.T) {
	httpTest(t, nil, func(s *agent.TestAgent) {

		ctx := queryOpts.Ctx()
		qCtx := ctx.Value("QueryOpts").(*QueryOpts)

		require.Equal(t, qCtx.Region, queryOpts.Region)
		require.Equal(t, qCtx.Namespace, queryOpts.Namespace)
		require.Equal(t, qCtx.AllowStale, queryOpts.AllowStale)
		require.Equal(t, qCtx.WaitIndex, queryOpts.WaitIndex)
		require.Equal(t, qCtx.WaitTime, queryOpts.WaitTime)
		require.Equal(t, qCtx.AuthToken, queryOpts.AuthToken)
		require.Equal(t, qCtx.PerPage, queryOpts.PerPage)
		require.Equal(t, qCtx.NextToken, queryOpts.NextToken)
		require.Equal(t, qCtx.Prefix, queryOpts.Prefix)
	})
}

func TestSetWriteOptions(t *testing.T) {
	httpTest(t, nil, func(s *agent.TestAgent) {
		ctx := writeOpts.Ctx()
		wCtx := ctx.Value("WriteOpts").(*WriteOpts)

		require.Equal(t, wCtx.Region, writeOpts.Region)
		require.Equal(t, wCtx.Namespace, writeOpts.Namespace)
		require.Equal(t, wCtx.AuthToken, writeOpts.AuthToken)
		require.Equal(t, wCtx.IdempotencyToken, writeOpts.IdempotencyToken)
	})
}

func TestTLS(t *testing.T) {
	if os.Getenv("NOMAD_TOKEN") == "" {
		t.Skip()
	}

	client, err := NewClient()
	require.NoError(t, err)

	q := &QueryOpts{
		Region:    globalRegion,
		Namespace: defaultNamespace,
	}
	result, meta, err := client.Jobs().GetJobs(q.Ctx())
	require.NoError(t, err)
	require.NotNil(t, meta)
	require.NotNil(t, result)
}

func TestTLSEnabled(t *testing.T) {
	enableTLS := func(c *agent.Config) {
		tC := c.TLSConfig
		tC.VerifyHTTPSClient = true
		tC.EnableHTTP = true
		tC.CAFile = mTLSFixturePath("server", "cafile")
		tC.CertFile = mTLSFixturePath("server", "certfile")
		tC.KeyFile = mTLSFixturePath("server", "keyfile")
	}
	httpTest(t, enableTLS, func(s *agent.TestAgent) {
		t.Run("client args", func(t *testing.T) {
			client, err := NewClient(
				WithTLSCerts(
					mTLSFixturePath("client", "cafile"),
					mTLSFixturePath("client", "certfile"),
					mTLSFixturePath("client", "keyfile"),
				),
				WithAddress(s.HTTPAddr()),
			)

			require.NoError(t, err)

			q := &QueryOpts{
				Region:    globalRegion,
				Namespace: defaultNamespace,
			}
			result, err := client.Status().Leader(q.Ctx())
			t.Logf("result: %q", *result)
			require.NoError(t, err)
			require.NotNil(t, result)
		})
		t.Run("env", func(t *testing.T) {
			t.Setenv("NOMAD_CACERT", mTLSFixturePath("client", "cafile"))
			t.Setenv("NOMAD_CLIENT_CERT", mTLSFixturePath("client", "certfile"))
			t.Setenv("NOMAD_CLIENT_KEY", mTLSFixturePath("client", "keyfile"))
			t.Setenv("NOMAD_ADDR", s.HTTPAddr())
			client, err := NewClient()
			require.NoError(t, err)

			q := &QueryOpts{
				Region:    globalRegion,
				Namespace: defaultNamespace,
			}
			result, err := client.Status().Leader(q.Ctx())
			require.NoError(t, err)
			t.Logf("result: %q", *result)
			require.NotNil(t, result)
		})
	})
}

func mTLSFixturePath(nodeType, pemType string) string {
	var filename string
	switch pemType {
	case "cafile":
		filename = "nomad-agent-ca.pem"
	case "certfile":
		filename = fmt.Sprintf("global-%s-nomad-0.pem", nodeType)
	case "keyfile":
		filename = fmt.Sprintf("global-%s-nomad-0-key.pem", nodeType)
	}

	return path.Join("../test_fixtures/mtls", filename)
}
