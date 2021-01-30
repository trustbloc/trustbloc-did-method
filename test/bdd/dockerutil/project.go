/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dockerutil

import (
	"fmt"
	"time"
)

// ComposeProject wraps all the docker-compose compositions of a given project
type ComposeProject struct {
	Name         string
	Compositions map[string]*Composition
	ServiceMap   map[string]string
	ComposeDirs  []string
	DockerHelper DockerHelper
}

// NewComposeProject generate a project of docker-compose compositions
func NewComposeProject(name string, composeDirs []string) *ComposeProject {
	cp := ComposeProject{
		Name:         name,
		Compositions: map[string]*Composition{},
		ServiceMap:   map[string]string{},
		ComposeDirs:  composeDirs,
		DockerHelper: NewDockerCmdlineHelper(),
	}

	return &cp
}

// Start starts the project, starting up all compositions.
func (cp *ComposeProject) Start(sleepDelay int) error {
	for _, dir := range cp.ComposeDirs {
		newComposition, err := NewComposition(cp.Name, "docker-compose.yml", dir)
		if err != nil {
			return fmt.Errorf("error composing system in BDD context: %w", err)
		}

		cp.Compositions[dir] = newComposition
	}

	fmt.Printf("docker-compose up ... waiting for %ds for containers to start ...", sleepDelay)
	time.Sleep(time.Second * time.Duration(sleepDelay))

	for dir, c := range cp.Compositions {
		serviceNames, err := c.GetServices()
		if err != nil {
			return fmt.Errorf("error fetching service names for dir '%s': %w", dir, err)
		}

		for _, name := range serviceNames {
			cp.ServiceMap[name] = dir
		}
	}

	return nil
}

// Close closes the project, decomposing all compositions.
// Will also remove any containers with the same project.Name prefix (eg. chaincode containers)
func (cp *ComposeProject) Close() error {
	for _, c := range cp.Compositions {
		if c != nil {
			if err := c.GenerateLogs("docker-compose.log"); err != nil {
				return err
			}

			if _, err := c.Decompose(); err != nil {
				return err
			}
		}
	}

	// Now remove associated chaincode containers if any
	err := cp.DockerHelper.RemoveContainersWithNamePrefix(cp.Name)

	if err != nil {
		return fmt.Errorf("removing chaincode containers for project '%s': %w", cp.Name, err)
	}

	return nil
}

// RestartServices restart the compositions in the project that contain the given services, given by service name
func (cp *ComposeProject) RestartServices(sleepDelay int, services []string, envs map[string]string) error {
	dirSet := map[string]struct{}{}

	for _, service := range services {
		dir, ok := cp.ServiceMap[service]
		if !ok {
			continue // service isn't in project
		}

		dirSet[dir] = struct{}{}
	}

	didNothing := true

	for dir := range dirSet {
		c, ok := cp.Compositions[dir]
		if !ok {
			return fmt.Errorf("missing composition for compose directory '%s'", dir)
		}

		err := c.Restart(envs)
		if err != nil {
			return fmt.Errorf("error restarting composition for '%s': %w", dir, err)
		}

		didNothing = false
	}

	if !didNothing {
		fmt.Printf("docker-compose up ... waiting for %ds for containers to start ...\n", sleepDelay)
		time.Sleep(time.Second * time.Duration(sleepDelay))
	}

	return nil
}
