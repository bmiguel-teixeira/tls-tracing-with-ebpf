PHONY: build run 

build:
	clang++ --std=c++17 -lbcc -o tls_tracer tls_tracer.cc

run: build
	# Usage is ./tls_tracer <ebpf_program.c> <path_to_binary_to_trace>
	# Example ./tls_tracer tls_tracer_ebpf_program.c /usr/lib/x86_64-linux-gnu/libssl.so.1.1

	# This run instruction tries to dynamically find the libssl library to attach the uprobe code.
	sudo find /usr/lib -wholename "*libssl.so*" -exec ./tls_tracer tls_tracer_ebpf_program.c {} \;

clean:
	rm tls_tracer

vagrant-run:
	vagrant up
	vagrant ssh -c "cd /app/c-cpp-version && sudo make run"

vagrant-test:
	# An exampel of a public endpoint with random data for testing.
	vagrant ssh -c "watch -n 1 curl -XGET https://gorest.co.in/public/v2/users"

vagrant-clean:
	vagrant destroy --force
