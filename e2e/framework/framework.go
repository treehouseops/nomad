package framework

import (
	"flag"
	"fmt"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/nomad/e2e/framework/provisioning"
)

const frameworkHelp = `
Usage: go test -v ./e2e [options]

These flags are coarse overrides for the test environment.

  -forceRun    skip all environment checks when filtering test suites
  -local       force default no-op provisioning
  -skipTests   skips all tests and only provisions
  -slow        include execution of slow test suites
  -showHelp    shows this help text

Provisioning flags tell the test runner to pre-provision the cluster before
running all tests. These flags can be passed to 'go test'. If no
'-provision.*' flag is set, the test runner assumes the cluster has already
been configured and uses the test environment's env vars to connect to the
cluster.

  -provision.terraform=string   pass file generated by terraform output
  -provision.vagrant=string     provision to a single-node vagrant box

Nomad version flags tell the provisioner to deploy a specific version of
Nomad. These flags are all ignored if no '-provision.*' flag is set.
Otherwise at most one should be set.

  -nomad.local_file=string  provision this specific local binary of Nomad
  -nomad.sha=string         provision this specific sha from S3
  -nomad.version=string     provision this version from releases.hashicorp.com

TestSuites can request Constraints on the Framework.Environment so that tests
are only run in the appropriate conditions. These environment flags provide
the information for those constraints.

  -env=string           name of the environment
  -env.arch=string      cpu architecture of the targets
  -env.os=string        operating system of the targets
  -env.provider=string  cloud provider of the environment
  -env.tags=string      comma delimited list of tags for the environment

`

var fHelp = flag.Bool("showHelp", false, "print the help screen")
var fLocal = flag.Bool("local", false,
	"denotes execution is against a local environment, forcing default no-op provisioning")
var fSlow = flag.Bool("slow", false, "toggles execution of slow test suites")
var fForceRun = flag.Bool("forceRun", false,
	"if set, skips all environment checks when filtering test suites")
var fSkipTests = flag.Bool("skipTests", false, "skip all tests and only provision")

// Provisioning flags
var fProvisionVagrant = flag.String("provision.vagrant", "",
	"run pre-provision to a single-node vagrant host")
var fProvisionTerraform = flag.String("provision.terraform", "",
	"run pre-provision from file generated by 'terraform output provisioning'")

// Nomad version flags
// TODO: these override each other. local_file > sha > version
// but we should assert at most 1 is set.
var fProvisionNomadLocalBinary = flag.String("nomad.local_file", "",
	"provision this specific local binary of Nomad (ignored for no-op provisioning).")
var fProvisionNomadSha = flag.String("nomad.sha", "",
	"provision this specific sha of Nomad (ignored for no-op provisioning)")
var fProvisionNomadVersion = flag.String("nomad.version", "",
	"provision this specific release of Nomad (ignored for no-op provisioning)")

// Environment flags
// TODO:
// if we have a provisioner, each target has its own environment. it'd
// be nice if we could match that environment against the tests so that
// we always avoid running tests that don't apply against the
// environment, and then have these flags override that behavior.
var fEnv = flag.String("env", "", "name of the environment executing against")
var fProvider = flag.String("env.provider", "",
	"cloud provider for which environment is executing against")
var fOS = flag.String("env.os", "",
	"operating system for which the environment is executing against")
var fArch = flag.String("env.arch", "",
	"cpu architecture for which the environment is executing against")
var fTags = flag.String("env.tags", "",
	"comma delimited list of tags associated with the environment")

var pkgFramework = New()

type Framework struct {
	suites      []*TestSuite
	provisioner provisioning.Provisioner
	env         Environment

	isLocalRun bool
	slow       bool
	force      bool
	skipAll    bool
}

// Environment contains information about the test target environment, used
// to constrain the set of tests run. See the environment flags above.
type Environment struct {
	Name     string
	Provider string
	OS       string
	Arch     string
	Tags     map[string]struct{}
}

// New creates a Framework
func New() *Framework {
	flag.Parse()
	if *fHelp {
		log.Fatal(frameworkHelp)
	}
	env := Environment{
		Name:     *fEnv,
		Provider: *fProvider,
		OS:       *fOS,
		Arch:     *fArch,
		Tags:     map[string]struct{}{},
	}
	for _, tag := range strings.Split(*fTags, ",") {
		env.Tags[tag] = struct{}{}
	}
	return &Framework{
		provisioner: provisioning.NewProvisioner(provisioning.ProvisionerConfig{
			IsLocal:          *fLocal,
			VagrantBox:       *fProvisionVagrant,
			TerraformConfig:  *fProvisionTerraform,
			NomadLocalBinary: *fProvisionNomadLocalBinary,
			NomadSha:         *fProvisionNomadSha,
			NomadVersion:     *fProvisionNomadVersion,
		}),
		env:        env,
		isLocalRun: *fLocal,
		slow:       *fSlow,
		force:      *fForceRun,
		skipAll:    *fSkipTests,
	}
}

// AddSuites adds a set of test suites to a Framework
func (f *Framework) AddSuites(s ...*TestSuite) *Framework {
	f.suites = append(f.suites, s...)
	return f
}

// AddSuites adds a set of test suites to the package scoped Framework
func AddSuites(s ...*TestSuite) *Framework {
	pkgFramework.AddSuites(s...)
	return pkgFramework
}

// Run starts the test framework, running each TestSuite
func (f *Framework) Run(t *testing.T) {
	info, err := f.provisioner.SetupTestRun(t, provisioning.SetupOptions{})
	if err != nil {
		t.Fatalf("could not provision cluster: %v", err)
	}
	defer f.provisioner.TearDownTestRun(t, info.ID)

	if f.skipAll {
		t.Skip("Skipping all tests, -skipTests set")
	}

	for _, s := range f.suites {
		t.Run(s.Component, func(t *testing.T) {
			skip, err := f.runSuite(t, s)
			if skip {
				t.Skipf("skipping suite '%s': %v", s.Component, err)
				return
			}
			if err != nil {
				t.Errorf("error starting suite '%s': %v", s.Component, err)
			}
		})
	}
}

// Run starts the package scoped Framework, running each TestSuite
func Run(t *testing.T) {
	pkgFramework.Run(t)
}

// runSuite is called from Framework.Run inside of a sub test for each TestSuite.
// If skip is returned as true, the test suite is skipped with the error text added
// to the Skip reason
// If skip is false and an error is returned, the test suite is failed.
func (f *Framework) runSuite(t *testing.T, s *TestSuite) (skip bool, err error) {

	// todo: remove
	if s.Component != "ConnectACLs" {
		return true, nil
	}

	// If -forceRun is set, skip all constraint checks
	if !f.force {
		// If this is a local run, check that the suite supports running locally
		if !s.CanRunLocal && f.isLocalRun {
			return true, fmt.Errorf("local run detected and suite cannot run locally")
		}

		// Check that constraints are met
		if err := s.Constraints.matches(f.env); err != nil {
			return true, fmt.Errorf("constraint failed: %v", err)
		}

		// Check the slow toggle and if the suite's slow flag is that same
		if f.slow != s.Slow {
			return true, fmt.Errorf("framework slow suite configuration is %v but suite is %v", f.slow, s.Slow)
		}
	}

	info, err := f.provisioner.SetupTestSuite(t, provisioning.SetupOptions{
		Name:         s.Component,
		ExpectConsul: s.Consul,
		ExpectVault:  s.Vault,
	})
	if err != nil {
		t.Fatalf("could not provision cluster: %v", err)
	}
	defer f.provisioner.TearDownTestSuite(t, info.ID)

	for _, c := range s.Cases {
		f.runCase(t, s, c)
	}

	return false, nil
}

func (f *Framework) runCase(t *testing.T, s *TestSuite, c TestCase) {

	// The test name is set to the name of the implementing type, including package
	name := fmt.Sprintf("%T", c)

	// The ClusterInfo handle should be used by each TestCase to isolate
	// job/task state created during the test.
	info, err := f.provisioner.SetupTestCase(t, provisioning.SetupOptions{
		Name:         name,
		ExpectConsul: s.Consul,
		ExpectVault:  s.Vault,
	})
	if err != nil {
		t.Errorf("could not provision cluster for case: %v", err)
	}
	defer f.provisioner.TearDownTestCase(t, info.ID)
	c.setClusterInfo(info)

	// Each TestCase runs as a subtest of the TestSuite
	t.Run(c.Name(), func(t *testing.T) {
		// If the TestSuite has Parallel set, all cases run in parallel
		if s.Parallel {
			t.Parallel()
		}

		f := newF(t)

		// Check if the case includes a before all function
		if beforeAllTests, ok := c.(BeforeAllTests); ok {
			beforeAllTests.BeforeAll(f)
		}

		// Check if the case includes an after all function at the end
		defer func() {
			if afterAllTests, ok := c.(AfterAllTests); ok {
				afterAllTests.AfterAll(f)
			}
		}()

		// Here we need to iterate through the methods of the case to find
		// ones that are test functions
		reflectC := reflect.TypeOf(c)
		for i := 0; i < reflectC.NumMethod(); i++ {
			method := reflectC.Method(i)
			if ok := isTestMethod(method.Name); !ok {
				continue
			}
			// Each test is run as its own sub test of the case
			// Test cases are never parallel
			t.Run(method.Name, func(t *testing.T) {

				cF := newFFromParent(f, t)
				if BeforeEachTest, ok := c.(BeforeEachTest); ok {
					BeforeEachTest.BeforeEach(cF)
				}
				defer func() {
					if afterEachTest, ok := c.(AfterEachTest); ok {
						afterEachTest.AfterEach(cF)
					}
				}()

				//Call the method
				method.Func.Call([]reflect.Value{reflect.ValueOf(c), reflect.ValueOf(cF)})
			})
		}
	})
}

func isTestMethod(m string) bool {
	if !strings.HasPrefix(m, "Test") {
		return false
	}
	// THINKING: adding flag to target a specific test or test regex?
	return true
}
