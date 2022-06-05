$script = <<-SCRIPT
apt update
apt install -y make clang libbpfcc-dev

wget https://go.dev/dl/go1.18.3.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.3.linux-amd64.tar.gz
rm -f go1.18.3.linux-amd64.tar.gz
echo export PATH=$PATH:/usr/local/go/bin >> /home/vagrant/.bashrc
echo export PATH=$PATH:/usr/local/go/bin >> /home/vagrant/.profile
SCRIPT

Vagrant.configure("2") do |config|
    config.vm.box = "alvistack/ubuntu-22.04"
    config.vm.provision "shell", inline: $script

    config.vm.synced_folder ".", "/app"
    config.vm.provider "virtualbox" do |vb|
        vb.memory = "2048"
        vb.cpus = "2"
    end
end
