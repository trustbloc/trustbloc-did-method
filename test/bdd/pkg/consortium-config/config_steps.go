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

	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/context"
)

// Steps is steps for VC BDD tests
type Steps struct {
	bddContext *context.BDDContext
	compose    string
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *context.BDDContext, composeProjectName string) *Steps {
	return &Steps{bddContext: ctx, compose: composeProjectName}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Consortium config is updated with config file "([^"]*)"$`, e.updateConfig)
	s.Step(`^Consortium config is generated with config file "([^"]*)"$`, e.generateConfig)
	s.Step(`^Consortium config is deleted$`, e.deleteConfig)
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
