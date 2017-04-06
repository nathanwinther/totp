# Time-based One-Time Password algorithm (TOTP).

Generate secrets, generate codes, and validate codes.
Compatible with Google Authenticator.

## Installation

This package can be installed with the go get command:

````
go get github.com/nathanwinther/totp.git
````

## Usage

````
package main

import (
  "fmt"
  "github.com/nathanwinther/totp"
)

func main() {
  secret, err := totp.CreateSecret(16)
  if err != nil {
    panic(err)
  }
  fmt.Println(secret)
  code, err := totp.GetCode(secret)
  if err != nil {
    panic(err)
  }
  fmt.Println(code)
  fmt.Println(totp.VerifyCode(secret, code, 2))
}
````