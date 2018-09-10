apt-get install gnupg2
gpg2 --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
gpg2 --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -

# Put into /etc/apt/sources.list.d/
(cat <<EOF
deb https://deb.torproject.org/torproject.org bionic main
deb-src https://deb.torproject.org/torproject.org bionic main
EOF
) > /etc/apt/sources.list.d/tor.list
apt-get update

apt-get install python3 virtualenv tor python3-pip openjdk-11-jre
