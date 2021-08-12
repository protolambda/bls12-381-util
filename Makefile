
download-tests:
	mkdir -p test-vectors
	wget https://github.com/ethereum/bls12-381-tests/releases/download/${BLS_TESTS_VERSION:=v0.1.0}/bls_tests_json.tar.gz -O - | tar -xz -C test-vectors
