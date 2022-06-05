# OpenSSL Library eBPF Tracer

This is a simplistic example on how to attach a ebpf probe to the OpenSSL Shared Library to trace TLS communication without any client instrumentation.
This version of the tracer is written C while the deployment code is done in Golang.

## Prerequisites

This example relies on the BCC framework. You can find more about it [here](https://github.com/iovisor/bcc)

Checkout how to install Vagrant [here](https://www.vagrantup.com/downloads)

# Test it out

```
make vagrant-run
```
It will bootstrap a local VM, build and run the eBPF program automatically.


```
make vagrant-test
```
It will execute a random cURL command inside the vagrant guest vm.
