/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package consortiumconfig

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/cucumber/godog"

	"github.com/trustbloc/trustbloc-did-method/test/bdd/dockerutil"
	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/context"
)

// Steps is steps for VC BDD tests
type Steps struct {
	bddContext *context.BDDContext
	compose    *dockerutil.ComposeProject
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *context.BDDContext, composeProject *dockerutil.ComposeProject) *Steps {
	return &Steps{bddContext: ctx, compose: composeProject}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Consortium config is updated with config file "([^"]*)"$`, e.updateConfig)
	s.Step(`^Consortium config is generated with config file "([^"]*)"$`, e.generateConfig)
	s.Step(`^Consortium config is deleted$`, e.deleteConfig)
	s.Step(`^DID method service is restarted with genesis file "([^"]*)"$`, e.restartDIDMethod)
	s.Step(`^Discovery services are restarted$`, e.restartDiscoveryServices)
}

func (e *Steps) generateConfig(config string) error {
	return execCMD("./generate_config.sh", config)
}

func (e *Steps) updateConfig(config string) error {
	return execCMD("./update_config.sh", config)
}

func (e *Steps) deleteConfig() error {
	return os.RemoveAll("./fixtures/wellknown/jws")
}

const sleepDelay = 5

// restarts did method as well as discovery services
//  setting the DID method service's genesis file path to the given value
func (e *Steps) restartDIDMethod(genesisFilePath string) error {
	err := e.compose.RestartServices(sleepDelay, []string{"trustbloc.did.method.example.com"},
		map[string]string{"GENESIS_FILES": genesisFilePath})
	if err != nil {
		return err
	}

	return e.restartDiscoveryServices()
}

func (e *Steps) restartDiscoveryServices() error {
	return e.compose.RestartServices(
		sleepDelay,
		[]string{"testnet.trustbloc.local", "stakeholder.one", "stakeholder.two"},
		nil,
	)
}

func execCMD(command string, args ...string) error {
	cmd := exec.Command(command, args...) // nolint: gosec

	var out bytes.Buffer

	var er bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &er

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf(er.String())
	}

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf(er.String())
	}

	return nil
}
