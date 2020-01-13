Configure Consul ACLs
=====================

This directory contains a set of scripts for re-configuring Consul in the e2e
environment to enable Consul ACLs. The intended pattern is to run against the
terraform'd environment in AWS.


## Steps

1) Append the `acl` HCL block to each Consul Server's configuration. This can
be done by simply uploading an additional file to each Consul Server's config
directory, the contents of which are appended on Consul agent start.

# some policies

# return the tokens somehow




# TF output we are working with
```
Apply complete! Resources: 19 added, 0 changed, 0 destroyed.

Outputs:

linux_clients = [
  "3.85.210.15",
  "34.204.42.11",
  "54.92.193.102",
  "54.221.14.235",
]
message = Your cluster has been provisioned! - To prepare your environment, run the
following:

```
export NOMAD_ADDR=http://3.80.214.107:4646
export CONSUL_HTTP_ADDR=http://3.80.214.107:8500
export NOMAD_E2E=1
```

Then you can run e2e tests with:

```
go test -v ./e2e
```

ssh into nodes with:
```
ssh -i keys/seth-e2e-smart-griffon.pem ubuntu@3.85.210.15
```

servers = [
  "3.80.214.107",
  "18.207.94.54",
  "54.152.185.44",
]
windows_clients = [
  "34.201.102.112",
]
```