package gateway.authz

import rego.v1

test_gateway_user_can_connect_to_mock_backend if {
	allow with input as {
		"action": "connect",
		"subject": {
			"sub": "user-123",
			"roles": ["gateway-user"],
		},
		"resource": {
			"name": "mock-backend",
			"port": 5678,
			"protocol": "tcp",
		},
	}
}

test_denies_unknown_service if {
	not allow with input as {
		"action": "connect",
		"subject": {
			"sub": "user-123",
			"roles": ["gateway-admin"],
		},
		"resource": {
			"name": "unlisted-service",
			"port": 5678,
			"protocol": "tcp",
		},
	}
}

test_denies_wrong_port_and_protocol if {
	not allow with input as {
		"action": "connect",
		"subject": {
			"sub": "user-123",
			"roles": ["gateway-user"],
		},
		"resource": {
			"name": "mock-backend",
			"port": 5679,
			"protocol": "udp",
		},
	}
}

test_denies_missing_identity if {
	not allow with input as {
		"action": "connect",
		"subject": {
			"sub": "",
			"roles": ["gateway-user"],
		},
		"resource": {
			"name": "mock-backend",
			"port": 5678,
			"protocol": "tcp",
		},
	}
}
