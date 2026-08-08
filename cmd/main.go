package main

import (
	"fmt"

	"github.com/CodeDynasty-dev/safetoken"
)

func main() {
	secret := "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f"
	auth, err := safetoken.New(safetoken.Config{Secret: secret})
	if err != nil {
		fmt.Printf("failed to create SafeToken instance: %v\n", err)
		return
	}

	payload := map[string]any{"email": "josiah89@kakdikas.now"}
	token, err := auth.Create(payload)
	if err != nil {
		fmt.Printf("failed to create token: %v\n", err)
		return
	}
	fmt.Println(token)

	decodedAccess, err := auth.Verify(token, "access")
	if err != nil {
		fmt.Printf("failed to verify access token: %v\n", err)
		return
	}

	fmt.Println(decodedAccess["email"])
	if decodedAccess["email"] != "josiah89@kakdikas.now" {
		fmt.Println("mismatched email in access token")
	}
}