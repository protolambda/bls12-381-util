
TESTS_VERSION=v0.0.3

download-tests:
	mkdir test-vectors
	wget https://github.com/ethereum/bls12-381-tests/releases/download/$(TESTS_VERSION)/bls_tests_json.tar.gz -O - | tar -xz -C test-vectors
