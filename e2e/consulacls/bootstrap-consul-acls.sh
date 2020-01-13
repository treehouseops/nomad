#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

tfstatefile="terraform/terraform.tfstate"

# Make sure we are running from the e2e/ directory
[ "$(basename "$(pwd)")" == "e2e" ] || (echo "must be run from nomad/e2e directory" && exit 1)

# Make sure terraform state file exists
[ -f "${tfstatefile}" ] || (echo "file ${tfstatefile} must exist (run terraform?)" && exit 1)

# Load Linux Client Node IPs from terraform state file
linux_clients=$(jq -r .outputs.linux_clients.value[] < "${tfstatefile}" | xargs)

# Load Windows Client Node IPs from terraform state file
windows_clients=$(jq -r .outputs.windows_clients.value[] < "${tfstatefile}" | xargs)

# Combine all the clients together
clients="${linux_clients} ${windows_clients}"

# Load Server Node IPs from terraform/terraform.tfstate
servers=$(jq -r .outputs.servers.value[] < "${tfstatefile}" | xargs)

# Use the 0th server as the ACL bootstrap server
server0=$(echo "${servers}" | cut -d' ' -f1)

# Find the .pem file to use
pemfile="terraform/$(jq -r '.resources[] | select(.name=="private_key_pem") | .instances[0].attributes.filename' < "terraform/terraform.tfstate")"

# See AWS service file
confdir="${confdir:-/etc/consul.d}"

# Not really present in the config
user=ubuntu

echo "==== SETUP configuration ====="
echo "SETUP servers: ${servers}"
echo "SETUP linux clients: ${linux_clients}"
echo "SETUP windows clients: ${windows_clients}"
echo "SETUP pem file: ${pemfile}"
echo "SETUP consul configs: ${confdir}"
echo "SETUP aws user: ${user}"
echo "SETUP bootstrap server: ${server0}"

function doSSH {
  server="$1"
  command="$2"
  echo "  will run command '${command}' on ${server}"
  ssh -o StrictHostKeyChecking=no -i "${pemfile}" "${user}@${server}" "${command}"
}

echo "=== CONFIGS ==="

# Upload acl.hcl to each Consul Server agent's configuration directory
for server in ${servers}; do
  echo "-> upload to ${server}"
  scp -o StrictHostKeyChecking=no -i "${pemfile}" consulacl/acl.hcl "${user}@${server}:/tmp/acl.hcl"
  doSSH "${server}" "sudo mv /tmp/acl.hcl ${confdir}/acl.hcl"
done

# Restart each Consul Server agent
for server in ${servers}; do
  echo "-> restart ${server} ..."
  doSSH "${server}" "sudo systemctl restart consul"
done

# Wait 20s before attempting bootstrap, otherwise Consul will return some
# nonsense Legacy mode error if the cluster is not yet stable.
echo "-> sleep 20s ..."
sleep 20

echo "=== ACL Bootstrap ==="

# Bootstrap Consul ACLs on server[0]
echo "-> bootstrap ACL using ${server0}"
consul_http_token=$(doSSH "${server0}" "/usr/local/bin/consul acl bootstrap" | grep SecretID | awk '{print $2}')
consul_http_addr="http://${server0}:8500"
export CONSUL_HTTP_TOKEN=${consul_http_token}
export CONSUL_HTTP_ADDR=${consul_http_addr}
echo "  consul http: ${CONSUL_HTTP_ADDR}"
echo "  consul root: ${CONSUL_HTTP_TOKEN}"

# Create Server Policy & Server agent tokens
echo "-> configure server policy"
consul acl policy create -name server-policy -rules @consulacl/server-policy.hcl

# Create & Set agent token for each Consul Server
for server in ${servers}; do
  echo "---> will create agent token for server ${server}"
  server_agent_token=$(consul acl token create -description "consul server agent token" -policy-name server-policy | grep SecretID | awk '{print $2}')
  echo "---> setting token for server agent: ${server} -> ${server_agent_token}"
  consul acl set-agent-token agent "${server_agent_token}"
  echo "---> done setting agent token for server ${server}"
done

# Wait 10s before continuing with linux_clients.
echo "-> sleep 10s"

# Create Client Policy & Client agent tokens
consul acl policy create -name client-policy -rules @consulacl/client-policy.hcl

# Create & Set agent token for each Consul Client (including windows)
for client in ${clients}; do
  echo "---> will create agent token for client ${client}"
  client_agent_token=$(consul acl token create -description "consul client agent token" -policy-name client-policy | grep SecretID | awk '{print $2}')
  echo "---> setting token for client agent: ${client} -> ${client_agent_token}"
  consul acl set-agent-token agent "${client_agent_token}"
  echo "---> done setting agent token for client ${client}"
done

echo "=== DONE ==="
echo ""
echo "for running tests ..."
echo "set CONSUL_HTTP_ADDR=${CONSUL_HTTP_ADDR}"
echo "set CONSUL_HTTP_TOKEN=${CONSUL_HTTP_TOKEN}"
