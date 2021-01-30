/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/trustbloc/trustbloc-did-method/test/bdd/dockerutil"
	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/cli"
	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/common"
	consortium_config "github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/consortium-config"
	bddctx "github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/context"
	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/vdri"
)

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all
	tags := "all"

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" {
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	status := runBDDTests(tags, format)
	if st := m.Run(); st > status {
		status = st
	}

	os.Exit(status)
}

func runBDDTests(tags, format string) int {
	return godog.RunWithOptions("godogs", func(s *godog.Suite) {
		var composeFiles = []string{"./fixtures/did-method-rest", "./fixtures/universalresolver",
			"./fixtures/sidetree-mock", "./fixtures/discovery-server", "./fixtures/stakeholder-server",
			"./fixtures/universal-registrar"}

		// generate a unique name, converting a uuid from bytes to a hex string without delimiters
		composeProjectName := fmt.Sprintf("%x", dockerutil.GenerateBytesUUID())

		composeProject := dockerutil.NewComposeProject(composeProjectName, composeFiles)

		s.BeforeSuite(func() {
			if os.Getenv("DISABLE_COMPOSITION") != "true" { // nolint: nestif
				// create dummy config files (that will be overwritten in tests)
				_, err := execCMD("./generate_stub_config.sh")
				if err != nil {
					panic(err.Error())
				}

				testSleep := 15
				if os.Getenv("TEST_SLEEP") != "" {
					var e error

					testSleep, e = strconv.Atoi(os.Getenv("TEST_SLEEP"))
					if e != nil {
						panic(fmt.Sprintf("Invalid value found in 'TEST_SLEEP': %s", e))
					}
				}

				err = composeProject.Start(testSleep)
				if err != nil {
					panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
				}
			}
		})
		s.AfterSuite(func() {
			err := composeProject.Close()
			if err != nil {
				panic(err)
			}

			err = os.RemoveAll("./fixtures/wellknown/jws")
			if err != nil {
				panic(err)
			}
		})
		FeatureContext(s, composeProject)
	}, godog.Options{
		Tags:          tags,
		Format:        format,
		Paths:         []string{"features"},
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	})
}

func execCMD(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...) // nolint: gosec

	var out bytes.Buffer

	var er bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &er

	err := cmd.Start()
	if err != nil {
		return "", fmt.Errorf(er.String())
	}

	err = cmd.Wait()
	if err != nil {
		return "", fmt.Errorf(er.String())
	}

	return out.String(), nil
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

func FeatureContext(s *godog.Suite, cp *dockerutil.ComposeProject) {
	bddContext, err := bddctx.NewBDDContext("fixtures/keys/tls/ec-cacert.pem", "fixtures/keys/tls/ec-pubCert.pem")
	if err != nil {
		panic(err.Error())
	}

	vdri.NewSteps(bddContext).RegisterSteps(s)
	common.NewSteps(bddContext).RegisterSteps(s)
	cli.NewSteps(bddContext).RegisterSteps(s)
	consortium_config.NewSteps(bddContext, cp).RegisterSteps(s)
}
