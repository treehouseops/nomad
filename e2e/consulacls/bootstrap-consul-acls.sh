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
consul_configs="/etc/consul.d"
nomad_configs="/etc/nomad.d"

# Not really present in the config
user=ubuntu

echo "==== SETUP configuration ====="
echo "SETUP servers: ${servers}"
echo "SETUP linux clients: ${linux_clients}"
echo "SETUP windows clients: ${windows_clients}"
echo "SETUP pem file: ${pemfile}"
echo "SETUP consul configs: ${consul_configs}"
echo "SETUP nomad configs: ${nomad_configs}"
echo "SETUP aws user: ${user}"
echo "SETUP bootstrap server: ${server0}"

function doSSH {
  hostname="$1"
  command="$2"
  echo "-----> will ssh command '${command}' on ${hostname}"
  ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i "${pemfile}" \
    "${user}@${hostname}" "${command}"
}

function doSCP {
  original="$1"
  username="$2"
  hostname="$3"
  destination="$4"
  echo "------> will scp ${original} to ${hostname}"
  scp \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i "${pemfile}" \
    "${original}" "${username}@${hostname}:${destination}"
}

echo "=== Consul Configs ==="

# Upload acl.hcl to each Consul Server agent's configuration directory
for server in ${servers}; do
  echo "-> upload acl.hcl to ${server}"
  doSCP "consulacls/acl.hcl" "${user}" "${server}" "/tmp/acl.hcl"
  doSSH "${server}" "sudo mv /tmp/acl.hcl ${consul_configs}/acl.hcl"
done

# Restart each Consul Server agent to pickup the new config
for server in ${servers}; do
  echo "-> restart Consul on ${server} ..."
  doSSH "${server}" "sudo systemctl restart consul"
done

# Wait 20s before attempting bootstrap, otherwise Consul will return some
# nonsense Legacy mode error if the cluster is not yet stable.
echo "-> sleep 20s ..."
sleep 20

echo "=== Consul ACL Bootstrap ==="

# Bootstrap Consul ACLs on server[0]
echo "-> bootstrap ACL using ${server0}"
consul_http_token=$(doSSH "${server0}" "/usr/local/bin/consul acl bootstrap" | grep SecretID | awk '{print $2}')
consul_http_addr="http://${server0}:8500"
export CONSUL_HTTP_TOKEN=${consul_http_token}
export CONSUL_HTTP_ADDR=${consul_http_addr}
echo "  consul http: ${CONSUL_HTTP_ADDR}"
echo "  consul root: ${CONSUL_HTTP_TOKEN}"

# Create Consul Server Policy & Consul Server agent tokens
echo "-> configure consul server policy"
consul acl policy create -name server-policy -rules @consulacls/consul-server-policy.hcl

# Create & Set agent token for each Consul Server
for server in ${servers}; do
  echo "---> will create agent token for server ${server}"
  server_agent_token=$(consul acl token create -description "consul server agent token" -policy-name server-policy | grep SecretID | awk '{print $2}')
  echo "---> setting token for server agent: ${server} -> ${server_agent_token}"
  consul acl set-agent-token agent "${server_agent_token}"
  echo "---> done setting agent token for server ${server}"
done

# Wait 10s before continuing with configuring consul clients.
echo "-> sleep 10s"
sleep 10

# Create Consul Client Policy & Client agent tokens
echo "-> configure consul client policy"
consul acl policy create -name client-policy -rules @consulacls/consul-client-policy.hcl

# Create & Set agent token for each Consul Client (including windows)
for client in ${clients}; do
  echo "---> will create consul agent token for client ${client}"
  client_agent_token=$(consul acl token create -description "consul client agent token" -policy-name client-policy | grep SecretID | awk '{print $2}')
  echo "---> setting consul token for consul client ${client} -> ${client_agent_token}"
  consul acl set-agent-token agent "${client_agent_token}"
  echo "---> done setting consul agent token for client ${client}"
done


echo "=== Nomad Configs ==="

# Create Nomad Server consul Policy and Nomad Server consul tokens
echo "-> configure nomad server policy & consul token"
consul acl policy create -name nomad-server-policy -rules @consulacls/nomad-server-policy.hcl
nomad_server_consul_token=$(consul acl token create -description "nomad server consul token" -policy-name nomad-server-policy | grep SecretID | awk '{print $2}')
nomad_server_consul_token_tmp=$(mktemp)
cp consulacls/nomad-server-consul.hcl "${nomad_server_consul_token_tmp}"
sed -i "s/CONSUL_TOKEN/${nomad_server_consul_token}/g" "${nomad_server_consul_token_tmp}"
for server in ${servers}; do
  echo "---> upload nomad-server-consul.hcl to ${server}"
  doSCP "${nomad_server_consul_token_tmp}" "${user}" "${server}" "/tmp/nomad-server-consul.hcl"
  doSSH "${server}" "sudo mv /tmp/nomad-server-consul.hcl ${nomad_configs}/nomad-server-consul.hcl"
done

# Create Nomad Client consul Policy and Nomad Client consul token
echo "-> configure nomad client policy & consul token"
consul acl policy create -name nomad-client-policy -rules @consulacls/nomad-client-policy.hcl
nomad_client_consul_token=$(consul acl token create -description "nomad client consul token" -policy-name nomad-client-policy | grep SecretID | awk '{print $2}')
nomad_client_consul_token_tmp=$(mktemp)
cp consulacls/nomad-client-consul.hcl "${nomad_client_consul_token_tmp}"
sed -i "s/CONSUL_TOKEN/${nomad_client_consul_token}/g" "${nomad_client_consul_token_tmp}"
for linux_client in ${linux_clients}; do
  echo "---> upload nomad-client-token.hcl to ${linux_client}"
  doSCP "${nomad_client_consul_token_tmp}" "${user}" "${linux_client}" "/tmp/nomad-client-consul.hcl"
  doSSH "${linux_client}" "sudo mv /tmp/nomad-client-consul.hcl ${nomad_configs}/nomad-client-consul.hcl"
done

# TODO: only apply Nomad Client changes to Linux nodes for now. Should add
# TODO: PS scripts to apply changes to Windows nodes as well.

# Restart each Nomad Server agent to pickup the new config
for server in ${servers}; do
  echo "-> restart Nomad Server on ${server} ..."
  doSSH "${server}" "sudo systemctl restart nomad"
done

# Give the Nomad servers a few seconds to start back up.
echo "-> sleep 5s for Nomad Servers ..."
sleep 5

# Restart each Nomad Client agent to pickup the new config
for linux_client in ${linux_clients}; do
  echo "-> restart Nomad Client on ${linux_client} ..."
  doSSH "${linux_client}" "sudo systemctl restart nomad"
done



# Give the Nomad Clients a few seconds to start back up.
echo "-> sleep 5s for Nomad Clients ..."
sleep 5

export NOMAD_ADDR="http://${server0}:4646"

echo "=== DONE ==="
echo ""
echo "for running tests ..."
echo "export CONSUL_HTTP_ADDR=${CONSUL_HTTP_ADDR}"
echo "export CONSUL_HTTP_TOKEN=${CONSUL_HTTP_TOKEN}"
echo "export NOMAD_ADDR=${NOMAD_ADDR}"
echo "export NOMAD_TEST_CONSUL_ACLS=1"
echo "export NOMAD_E2E=1"
echo "... and then run 'go test -v' in e2e/"
