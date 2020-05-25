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
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/trustbloc/trustbloc-did-method/test/bdd/dockerutil"
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

// nolint: gocognit,gocyclo
func runBDDTests(tags, format string) int {
	return godog.RunWithOptions("godogs", func(s *godog.Suite) {
		var composition []*dockerutil.Composition
		var composeFiles = []string{"./fixtures/did-method-rest", "./fixtures/universalresolver",
			"./fixtures/sidetree-mock", "./fixtures/discovery-server", "./fixtures/stakeholder-server",
			"./fixtures/universal-registrar"}
		s.BeforeSuite(func() {
			if os.Getenv("DISABLE_COMPOSITION") != "true" {
				// Need a unique name, but docker does not allow '-' in names
				composeProjectName := strings.ReplaceAll(generateUUID(), "-", "")

				for _, v := range composeFiles {
					newComposition, err := dockerutil.NewComposition(composeProjectName, "docker-compose.yml", v)
					if err != nil {
						panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
					}
					composition = append(composition, newComposition)
				}
				fmt.Println("docker-compose up ... waiting for containers to start ...")
				testSleep := 15
				if os.Getenv("TEST_SLEEP") != "" {
					var e error

					testSleep, e = strconv.Atoi(os.Getenv("TEST_SLEEP"))
					if e != nil {
						panic(fmt.Sprintf("Invalid value found in 'TEST_SLEEP': %s", e))
					}
				}
				fmt.Printf("*** testSleep=%d", testSleep)
				time.Sleep(time.Second * time.Duration(testSleep))

				// create config files
				_, err := execCMD("../../.build/bin/cli", "create-config",
					"--sidetree-url", "https://localhost:48326/sidetree/0.0.1", "--tls-cacerts",
					"../../test/bdd/fixtures/keys/tls/ec-cacert.pem", "--sidetree-write-token", "rw_token", "--config-file",
					"./fixtures/wellknown/config.json", "--output-directory", "../../test/bdd/fixtures/wellknown/jws")
				if err != nil {
					panic(err.Error())
				}
			}
		})
		s.AfterSuite(func() {
			for _, c := range composition {
				if c != nil {
					if err := c.GenerateLogs(c.Dir, "docker-compose.log"); err != nil {
						panic(err)
					}
					if _, err := c.Decompose(c.Dir); err != nil {
						panic(err)
					}
				}
			}
		})
		FeatureContext(s)
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

// generateUUID returns a UUID based on RFC 4122
func generateUUID() string {
	id := dockerutil.GenerateBytesUUID()
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func FeatureContext(s *godog.Suite) {
	bddContext, err := bddctx.NewBDDContext("fixtures/keys/tls/ec-cacert.pem")
	if err != nil {
		panic(err.Error())
	}

	vdri.NewSteps(bddContext).RegisterSteps(s)
}
