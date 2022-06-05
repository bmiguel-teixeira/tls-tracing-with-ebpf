PHONY: run 

run:
	go run -exec sudo main.go

vagrant-run:
	vagrant up
	vagrant ssh -c "cd /app/golang-version && make run"

vagrant-test:
	# An exampel of a public endpoint with random data for testing.
	vagrant ssh -c "watch -n 1 curl -XGET https://ebpf.io/"

vagrant-clean:
	vagrant destroy --force
