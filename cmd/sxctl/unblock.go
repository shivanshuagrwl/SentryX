package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var unblockCmd = &cobra.Command{
	Use:   "unblock <ip>",
	Short: "Remove an IPv4 address from the blocklist",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]
		if err := apiRequest("DELETE", "/api/rules/"+ip, nil, nil); err != nil {
			return err
		}
		fmt.Printf("✓ unblocked %s\n", ip)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unblockCmd)
}
