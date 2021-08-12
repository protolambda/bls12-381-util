
download-tests:
	mkdir test-vectors
	wget https://github.com/ethereum/bls12-381-tests/releases/download/$(cat .bls-tests-version.txt)/bls_tests_json.tar.gz -O - | tar -xz -C test-vectors
