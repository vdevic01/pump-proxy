package saservice

type SAServiceForbiddenError struct {
	Msg string
	Err error
}

func (e *SAServiceForbiddenError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

func (e *SAServiceForbiddenError) Unwrap() error {
	return e.Err
}

type SAServiceInternalError struct {
	Msg string
	Err error
}

func (e *SAServiceInternalError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

func (e *SAServiceInternalError) Unwrap() error {
	return e.Err
}
