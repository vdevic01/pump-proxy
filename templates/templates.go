package templates

import (
	"os"
)

func ReadSigninPage() (page []byte, err error) {
	signinPage, err := os.ReadFile("templates/signin.html")
	if err != nil {
		return nil, err
	}
	return signinPage, nil
}
