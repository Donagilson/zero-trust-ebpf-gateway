package gateway.authz

import rego.v1

default allow := false

# The backend must populate subject claims from a verified Keycloak token and
# resolve the requested resource to this service name before asking OPA.
service_access := {
	"mock-backend": {
		"port": 5678,
		"protocol": "tcp",
		"roles": {"gateway-user", "gateway-admin"},
	},
}

allow if {
	input.action == "connect"
	is_string(input.subject.sub)
	input.subject.sub != ""
	is_array(input.subject.roles)
	is_string(input.resource.name)

	service := service_access[input.resource.name]
	input.resource.port == service.port
	input.resource.protocol == service.protocol

	some role in input.subject.roles
	role in service.roles
}
