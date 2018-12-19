#!/bin/bash

echo "Install-vagrant.sh starts running"

APTGET="sudo DEBIAN_FRONTEND=noninteractive apt-get"
APTGETINSTALL="$APTGET -y install"
PIP="sudo -H pip3"
PIPINSTALL="$PIP install"
VENVPIP=" sudo -H venv/bin/pip3"
VPIPINSTALL="$VENVPIP install"

echo "Updating the packages"
$APTGET update

echo "Installing gnupg2"
$APTGETINSTALL gnupg2
gpg2 --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
gpg2 --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -

echo "Put sources into /etc/apt/sources.list.d"
sudo tee -a /etc/apt/sources.list.d/tor.list << END
deb https://deb.torproject.org/torproject.org bionic main
deb-src https://deb.torproject.org/torproject.org bionic main
END


$APTGET update
$APTGET upgrade

if ! hash python 2>/dev/null; then
	echo "Installing python"
	$APTGETINSTALL python
else
	echo "Python is already installed"
fi

if ! hash python3 2>/dev/null; then
	echo "Installing python3"
	$APTGETINSTALL python3
else
	echo "Python3 is already installed"
fi

if ! hash pip3 2>/dev/null; then
	echo "Installing pip"
	$APTGETINSTALL python3-pip
	$PIPINSTALL --upgrade pip
else
	echo "Pip is already installed"
fi

if ! hash git 2>/dev/null; then
	echo "Installing git"
	$APTGETINSTALL git
else
	echo "Git is already installed"
fi

if ! hash virtualenv 2>/dev/null; then
	echo "Installing virtualenv"
	$APTGETINSTALL virtualenv
else
	echo "Virtualenv is already installed"
fi

cd /vagrant
virtualenv --python=python3 venv
source venv/bin/activate
$VPIPINSTALL -r requirements.txt -r requirements-proxy.txt
$VPIPINSTALL pytest

if ! [ -d "chutney" ]; then
	echo "Installing chutney"	
	cd /home/vagrant
	git clone https://github.com/torproject/chutney.git
	cp /vagrant/tools/chutney/small-chut chutney
	sudo chown -R vagrant:vagrant chutney/
	cd chutney
	git apply /vagrant/tools/chutney/sandbox_patch
else
	echo "Chutney is already installed"
fi

echo "Installing TOR client"
$APTGETINSTALL tor openjdk-11-jre
