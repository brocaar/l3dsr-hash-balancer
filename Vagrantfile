# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"

  profile = <<-PROFILE
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=/home/vagrant
  PROFILE

  config.vm.provision "shell", inline: <<-SHELL
    apt-get install -y git libpcap-dev
    wget --progress=bar:force https://storage.googleapis.com/golang/go1.5.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.5.linux-amd64.tar.gz
    mkdir -p /home/vagrant/src/github.com/brocaar
    chown -R vagrant:vagrant /home/vagrant/src
    ln -s /vagrant /home/vagrant/src/github.com/brocaar/l3dsr-hash-balancer

    echo '#{profile}' >> /home/vagrant/.profile
  SHELL

  config.vm.define "balancer" do |balancer|
    balancer.vm.network "private_network", ip: "192.168.33.10"
    balancer.vm.provision "shell", inline: <<-SHELL
      # drop RST packets sent by the kernel because the port hasn't been opened
      # but ignore when DSCP has been set to 1 (application generated RST)
      iptables -A OUTPUT -m dscp ! --dscp 1 -s 192.168.33.10 -p tcp --tcp-flags RST RST -j DROP
    SHELL
  end

  config.vm.define "backend" do |backend|
    backend.vm.network "private_network", ip: "192.168.33.20", mac: "08002733d163"
    backend.vm.network "private_network", ip: "192.168.33.30"
    backend.vm.provision "shell", inline: <<-SHELL
      # drop RST packets sent by the kernel because the port hasn't been opened
      # but ignore when DSCP has been set to 1 (application generated RST)
      iptables -A OUTPUT -m dscp ! --dscp 1 -s 192.168.33.20 -p tcp --tcp-flags RST RST -j DROP

      apt-get install -y nginx
      sed -i "s/listen 80 default_server/listen 192.168.33.30:80 default_server/" /etc/nginx/sites-enabled/default
      service nginx restart
    SHELL
  end
end
