package cmd

import (
	"fmt"
	"strings"
)

type OptionMap map[string]string

func (m *OptionMap) String() string {
	if m == nil {
		return "{}"
	}

	return fmt.Sprintf("%v", *m)
}

func (m *OptionMap) Set(value string) error {
	parts := strings.SplitN(value, "=", 2)

	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("Argument format is <key>=<value>")
	}

	(*m)[parts[0]] = parts[1]

	return nil
}
