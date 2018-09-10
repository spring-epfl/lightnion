Vagrant.configure("2") do |config|
  config.vm.define :torMachine do |torMachine|
    torMachine.vm.box = "ubuntu/bionic64"
    torMachine.vm.hostname = "torMachine"
    torMachine.vm.network "forwarded_port", guest: 4990, host: 4990 
    torMachine.vm.network "forwarded_port", guest: 8765, host: 8765

    torMachine.vm.provider "virtualbox" do |v|
      v.memory = 4096
      v.cpus = 2
    end
  end
end
