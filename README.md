# sshaudit

![CI](https://github.com/onaio/sshaudit/workflows/CI/badge.svg)
[![codecov](https://codecov.io/gh/evansmurithi/sshaudit/branch/main/graph/badge.svg?token=raBX0FtVdW)](https://codecov.io/gh/evansmurithi/sshaudit)
[![Go Report Card](https://goreportcard.com/badge/github.com/onaio/sshaudit)](https://goreportcard.com/report/github.com/onaio/sshaudit)

Go package for working with https://www.sshaudit.com/

## Installation

`sshaudit` can be installed using:

```sh
go get github.com/onaio/sshaudit
```

## Basic Usage

### Initializing client

You should provide your application name and version when initializing your client. They'll be used in setting the `User-Agent` request header.

```Go
appName := "test app"
appVersion := "v1.2.3"
client, err := sshaudit.NewClient(appName, appVersion)
```

### Standard SSH audit

To run a standard audit on a given server:

```Go
server := "93.184.216.34"  // can be hostname or IPv4/IPv6 address
port := 22
info, err := client.StandardServerAudit(server, port)
```

### Policy SSH audit

To run a policy audit on a given server:

```Go
server := "93.184.216.34"  // can be hostname or IPv4/IPv6 address
port := 22
policyName := "Hardened Ubuntu Server 20.04 LTS (version 1)"
info, err := client.PolicyServerAudit(server, port, policyName)
```
