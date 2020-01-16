package connect

import (
	"os"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/nomad/e2e/e2eutil"
	"github.com/hashicorp/nomad/e2e/framework"
	"github.com/hashicorp/nomad/helper/uuid"
	"github.com/hashicorp/nomad/jobspec"
	"github.com/stretchr/testify/require"
)

type ConnectACLsE2ETest struct {
	framework.TC

	// things to cleanup after each test case
	jobIDs          []string
	consulPolicyIDs []string
	consulTokenIDs  []string
}

func (tc *ConnectACLsE2ETest) BeforeAll(f *framework.F) {
	if os.Getenv("NOMAD_TEST_CONSUL_ACLS") != "1" {
		f.T().Skip("skipping test that uses Consul ACLs")
	}

	if os.Getenv("CONSUL_HTTP_TOKEN") == "" {
		f.T().Fatal("requires CONSUL_HTTP_TOKEN with root Consul ACL token")
	}

	e2eutil.WaitForLeader(f.T(), tc.Nomad())
	e2eutil.WaitForNodesReady(f.T(), tc.Nomad(), 2)
}

func (tc *ConnectACLsE2ETest) AfterEach(f *framework.F) {
	if os.Getenv("NOMAD_TEST_SKIPCLEANUP") == "1" {
		return
	}

	r := require.New(f.T())

	// cleanup jobs
	for _, id := range tc.jobIDs {
		_, _, err := tc.Nomad().Jobs().Deregister(id, true, nil)
		r.NoError(err)
	}

	// cleanup consul tokens
	for _, id := range tc.consulTokenIDs {
		_, err := tc.Consul().ACL().TokenDelete(id, nil)
		r.NoError(err)
	}

	// cleanup consul policies
	for _, id := range tc.consulPolicyIDs {
		_, err := tc.Consul().ACL().PolicyDelete(id, nil)
		r.NoError(err)
	}

	// do garbage collection
	err := tc.Nomad().System().GarbageCollect()
	r.NoError(err)

	tc.jobIDs = []string{}
	tc.consulTokenIDs = []string{}
	tc.consulPolicyIDs = []string{}
}

// todo: replace this with the real nomad implementation
type consulPolicy struct {
	Name  string // e.g. nomad-operator
	Rules string // e.g. service "" { policy="write" }
}

func (tc *ConnectACLsE2ETest) createConsulPolicy(p consulPolicy, f *framework.F) string {
	r := require.New(f.T())
	result, _, err := tc.Consul().ACL().PolicyCreate(&api.ACLPolicy{
		Name:        p.Name,
		Description: "test policy " + p.Name,
		Rules:       p.Rules,
	}, nil)
	r.NoError(err, "failed to create consul policy")
	return result.ID
}

func (tc *ConnectACLsE2ETest) createOperatorToken(policyID string, f *framework.F) string {
	r := require.New(f.T())
	token, _, err := tc.Consul().ACL().TokenCreate(&api.ACLToken{
		Description: "operator token",
		Policies:    []*api.ACLTokenPolicyLink{{ID: policyID}},
	}, nil)
	r.NoError(err, "failed to create operator token")
	return token.SecretID
}

func (tc *ConnectACLsE2ETest) TestConnectACLsRegisterRootToken(f *framework.F) {
	t := f.T()
	r := require.New(t)

	t.Log("test register Connect job w/ ACLs enabled w/ root token")

	jobID := "connect" + uuid.Generate()[0:8]
	tc.jobIDs = append(tc.jobIDs, jobID)
	jobAPI := tc.Nomad().Jobs()

	job, err := jobspec.ParseFile("connect/input/demo.nomad")
	r.NoError(err)

	resp, _, err := jobAPI.Register(job, nil)
	r.NoError(err)
	r.NotNil(resp)
	r.Zero(resp.Warnings)
}

func (tc *ConnectACLsE2ETest) TestConnectACLsRegisterOperatorToken(f *framework.F) {
	t := f.T()
	r := require.New(t)

	rootToken := os.Getenv("CONSUL_HTTP_TOKEN")
	defer func() {
		t.Log("restore root token:", rootToken)
		_ = os.Setenv("CONSUL_HTTP_TOKEN", rootToken)
	}()

	_ = os.Setenv("CONSUL_HTTP_TOKEN", "")

	t.Log("test register Connect job w/ ACLs enabled w/ operator token")

	policyID := tc.createConsulPolicy(consulPolicy{
		Name:  "nomad-operator-policy",
		Rules: `service "example" { policy = "write" }`,
	}, f)

	t.Log("created operator policy:", policyID)

	tokenID := tc.createOperatorToken(policyID, f)

	t.Log("created operator token:", tokenID)

	// do something broken, see if we actually use passed in token
	badID := uuid.Generate()
	job, err := jobspec.ParseFile("connect/input/demo.nomad")
	r.NoError(err)

	jobAPI := tc.Nomad().Jobs()

	// todo: need to set consul token on the job
	job.ConsulToken = &badID

	// allow unauthenticated is not set to false, should be!
	// also, this should fail if they provide a token but is not enforced

	resp, _, err := jobAPI.Register(job, nil)
	r.Error(err)

	t.Log("warnings:", resp.Warnings)
}
