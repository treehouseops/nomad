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

const (
	// envConsulToken is the consul http token environment variable
	envConsulToken = "CONSUL_HTTP_TOKEN"

	// demoConnectJob is the example connect enabled job useful for testing
	demoConnectJob = "connect/input/demo.nomad"
)

// Note: currently requires feature branch build of Nomad (i.e. the one with
// all the features!)
// Set this before doing terraform apply (for now).
//    export TF_VAR_nomad_sha=4c2818211ec9ef94e27ba95b3e1bcf5e9dbd29ae
//    export NOMAD_TEST_CONSUL_ACLS=1

type ConnectACLsE2ETest struct {
	framework.TC

	consulMasterToken string

	// things to cleanup after each test case
	jobIDs          []string
	consulPolicyIDs []string
	consulTokenIDs  []string
}

func (tc *ConnectACLsE2ETest) unsetConsulToken() {
	os.Setenv(envConsulToken, "")
}

func (tc *ConnectACLsE2ETest) setConsulToken() {
	os.Setenv(envConsulToken, tc.consulMasterToken)
}

func (tc *ConnectACLsE2ETest) BeforeAll(f *framework.F) {
	if os.Getenv("NOMAD_TEST_CONSUL_ACLS") != "1" {
		f.T().Skip("skipping test that uses Consul ACLs")
	}

	// store the consul master token so it can be restored after each test
	if tc.consulMasterToken = os.Getenv(envConsulToken); tc.consulMasterToken == "" {
		f.T().Fatal("requires CONSUL_HTTP_TOKEN with master Consul ACL token")
	}

	// TODO: this is probably messed up due to ACLs...
	e2eutil.WaitForLeader(f.T(), tc.Nomad())
	e2eutil.WaitForNodesReady(f.T(), tc.Nomad(), 2)
}

func (tc *ConnectACLsE2ETest) AfterEach(f *framework.F) {
	if os.Getenv("NOMAD_TEST_SKIPCLEANUP") == "1" {
		return
	}

	r := require.New(f.T())
	log := f.T().Log

	// reset the consul master token, so that cleanup works
	tc.setConsulToken()

	// cleanup jobs
	for _, id := range tc.jobIDs {
		log("cleanup: deregister nomad job id:", id)
		_, _, err := tc.Nomad().Jobs().Deregister(id, true, nil)
		r.NoError(err)
	}

	// cleanup consul tokens
	for _, id := range tc.consulTokenIDs {
		log("cleanup: delete consul token id:", id)
		_, err := tc.Consul().ACL().TokenDelete(id, nil)
		r.NoError(err)
	}

	// cleanup consul policies
	for _, id := range tc.consulPolicyIDs {
		log("cleanup: delete consul policy id:", id)
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
	tc.consulPolicyIDs = append(tc.consulPolicyIDs, result.ID)
	return result.ID
}

func (tc *ConnectACLsE2ETest) createOperatorToken(policyID string, f *framework.F) string {
	r := require.New(f.T())
	token, _, err := tc.Consul().ACL().TokenCreate(&api.ACLToken{
		Description: "operator token",
		Policies:    []*api.ACLTokenPolicyLink{{ID: policyID}},
	}, nil)
	r.NoError(err, "failed to create operator token")
	tc.consulTokenIDs = append(tc.consulTokenIDs, token.AccessorID)
	return token.SecretID
}

func (tc *ConnectACLsE2ETest) TestConnectACLsRegister_MasterToken(f *framework.F) {
	t := f.T()
	r := require.New(t)

	t.Skip("TODO broken for now") // todo: fix policy parsing to support master token semantics

	t.Log("test register Connect job w/ ACLs enabled w/ master token")

	jobID := "connect" + uuid.Generate()[0:8]
	tc.jobIDs = append(tc.jobIDs, jobID)

	jobAPI := tc.Nomad().Jobs()

	job, err := jobspec.ParseFile(demoConnectJob)
	r.NoError(err)

	// Set the job file to use the consul master token.
	// One should never do this in practice, but, it should work.
	// https://www.consul.io/docs/acl/acl-system.html#builtin-tokens
	//
	// note: We cannot just set the environment variable when using the API
	// directly - that only works when using the nomad CLI command which does
	// the step of converting the environment variable into a set option.
	job.ConsulToken = &tc.consulMasterToken

	resp, _, err := jobAPI.Register(job, nil)
	r.NoError(err)
	r.NotNil(resp)
	r.Zero(resp.Warnings)
}

func (tc *ConnectACLsE2ETest) TestConnectACLsRegister_MissingOperatorToken(f *framework.F) {
	t := f.T()
	r := require.New(t)

	tc.unsetConsulToken()

	t.Log("test register Connect job w/ ACLs enabled w/o operator token")

	job, err := jobspec.ParseFile(demoConnectJob)
	r.NoError(err)

	tc.unsetConsulToken()

	jobAPI := tc.Nomad().Jobs()

	// Explicitly show the ConsulToken is not set
	job.ConsulToken = nil

	_, _, err = jobAPI.Register(job, nil)
	r.Error(err)

	t.Log("job correctly rejected, with error:", err)
}

func (tc *ConnectACLsE2ETest) TestConnectACLsRegister_FakeOperatorToken(f *framework.F) {
	t := f.T()
	r := require.New(t)

	t.Log("test register Connect job w/ ACLs enabled w/ operator token")

	policyID := tc.createConsulPolicy(consulPolicy{
		Name:  "nomad-operator-policy",
		Rules: `service "count-api" { policy = "write" }`,
	}, f)
	t.Log("created operator policy:", policyID)

	// do something broken, see if we actually use passed in token
	badID := uuid.Generate()
	job, err := jobspec.ParseFile("connect/input/demo.nomad")
	r.NoError(err)

	tc.unsetConsulToken()

	jobAPI := tc.Nomad().Jobs()

	// deliberately set an invalid Consul token
	job.ConsulToken = &badID

	// should fail, because the token is garbage
	_, _, err = jobAPI.Register(job, nil)
	r.Error(err)
	t.Log("job correctly rejected, with error:", err)
}

func (tc *ConnectACLsE2ETest) TestConnectACLsRegister_RealOperatorToken(f *framework.F) {
	t := f.T()
	r := require.New(t)

	t.Log("test register Connect job w/ ACLs enabled w/ operator token")

	policyID := tc.createConsulPolicy(consulPolicy{
		Name:  "nomad-operator-policy",
		Rules: `service "count-api" { policy = "write" }`,
	}, f)
	t.Log("created operator policy:", policyID)

	tokenID := tc.createOperatorToken(policyID, f)
	t.Log("created operator token:", tokenID)

	job, err := jobspec.ParseFile("connect/input/demo.nomad")
	r.NoError(err)

	// nomad Server needs a acl:write token
	// nomad Client needs a <> token

	tc.unsetConsulToken()

	jobAPI := tc.Nomad().Jobs()

	// set the valid operator token we just created
	job.ConsulToken = &tokenID

	// should succeed
	resp, _, err := jobAPI.Register(job, nil)
	r.NoError(err)
	r.NotNil(resp)
	r.Empty(resp.Warnings)
}
