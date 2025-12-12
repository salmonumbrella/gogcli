package googleapi

import "fmt"

type AuthRequiredError struct {
	Service string
	Email   string
	Cause   error
}

func (e *AuthRequiredError) Error() string {
	return fmt.Sprintf("auth required for %s %s", e.Service, e.Email)
}

func (e *AuthRequiredError) Unwrap() error {
	return e.Cause
}
