package server

import "fmt"

func StartMcpServer(transport string) error {
	fmt.Println("Starting MCP server...")
	fmt.Println("Transport protocol:", transport)
	return nil
}
