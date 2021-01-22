#!/bin/bash

# This script is used to run vagrant based tests on Travis.
# This script is started via sudo from .travis.yml

set -e
set -x

FEDORA_VERSION=33
FEDORA_BOX_VERSION=33.20201019.0

setup() {
	vagrant init fedora/${FEDORA_VERSION}-cloud-base --box-version ${FEDORA_BOX_VERSION}
	vagrant up --no-tty
	mkdir -p ~/.ssh
	vagrant ssh-config >> ~/.ssh/config
	ssh -i .vagrant/machines/default/virtualbox/private_key -R default vagrant@127.0.0.1 -p 2222 sudo dnf install -y gcc git gnutls-devel nftables-devel libaio-devel \
		libasan libcap-devel libnet-devel libnl3-devel make protobuf-c-devel \
		protobuf-devel python3-flake8 python3-future python3-protobuf \
		python3-junit_xml rubygem-asciidoctor iptables libselinux-devel libbpf-devel
	# Disable sssd to avoid zdtm test failures in pty04 due to sssd socket
        ssh -i .vagrant/machines/default/virtualbox/private_key -R default vagrant@127.0.0.1 -p 2222 sudo systemctl mask sssd
        ssh -i .vagrant/machines/default/virtualbox/private_key -R default vagrant@127.0.0.1 -p 2222 cat /proc/cmdline
}

fedora-no-vdso() {
	ssh default sudo grubby --update-kernel ALL --args="vdso=0"
	vagrant reload
	ssh default cat /proc/cmdline
	ssh default 'cd /vagrant; tar xf criu.tar; cd criu; make -j 4'
	# Excluding two cgroup tests which seem to fail because of cgroup2
	ssh default 'cd /vagrant/criu/test; sudo ./zdtm.py run -a --keep-going'
}

$1
