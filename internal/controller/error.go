package controller

import "errors"

var (
	errIssuerIsExist    = errors.New("issuer is exist")
	errIssuerIsNotExist = errors.New("issuer is notexist")
)
