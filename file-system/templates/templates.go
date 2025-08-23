package templates

import (
	"fmt"
	"os"
)

func ReadSigninPage() (page []byte, err error) {
	signinPage, err := os.ReadFile("templates/signin.html")
	if err != nil {
		return nil, fmt.Errorf("error reading sign in page: %w", err)
	}
	return signinPage, nil
}
