# OpenSSL Library eBPF Tracer

This is a simplistic example on how to attach a ebpf probe to the OpenSSL Shared Library to trace TLS communication without any client instrumentation.
This version of the tracer is written in pure C/C++.

## Prerequisites

This example relies on the BCC framework. You can find more about it [here](https://github.com/iovisor/bcc)

You will require the following to compile and deploy it locally in your Ubuntu Machine

```
apt update
apt install -y make clang libbpfcc-dev
```

You can also rely on Vagrant to bootstrap a test environment for this example.
Checkout how to install Vagrant [here](https://www.vagrantup.com/downloads)

# Test it out

## If using your **host machine**
```
sudo make run
```

It will build & run the ebpf program directly in your host machine.

To test it out, just run a random cURL command like 
```
curl -XGET https://github.com
```
in a different terminal and you should see the contents of the entire HTTP request being captured.


## If using **Vagrant**

```
make vagrant-run
```
It will bootstrap a local VM, build and run the eBPF program automatically.


```
make vagrant-test
```
It will execute a random cURL command inside the vagrant guest vm.
