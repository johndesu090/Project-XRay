#!/bin/bash

set -e

usage() {
  echo "Usage: ${0} [-p|--port]" 1>&2
  exit 1
}

command_exists() {
    type "$1" &> /dev/null;
}

install_unzip() {
    if ! command_exists unzip; then
      if command_exists apt-get; then
              sudo apt-get -y -q install unzip xz-utils
          elif command_exists yum; then
              sudo yum -y install unzip
          fi
          if ! command_exists unzip;then
              echo "command unzip not found"
              exit 1;
          fi
    fi
}

install_node() {
  if ! command_exists node; then
      wget -q https://nodejs.org/dist/v18.15.0/node-v18.15.0-linux-x64.tar.xz
      tar -xvf node-v18.15.0-linux-x64.tar.xz
      sudo mkdir -p /usr/local/nodejs
      sudo mv node-v18.15.0-linux-x64/* /usr/local/nodejs/
      sudo ln -s /usr/local/nodejs/bin/node /usr/local/bin
      sudo ln -s /usr/local/nodejs/bin/npm /usr/local/bin
  fi
}

install_pm2() {
  if ! command_exists pm2; then
      npm i -g pm2
      sudo ln -s /usr/local/nodejs/bin/pm2 /usr/local/bin
  fi
}

PORT=8080

while [[ $# -gt 0 ]];do
  key=${1}
  case ${key} in
    -p|--port)
      PORT=${2}
      shift 2
      ;;
    *)
      usage
      shift
      ;;
  esac
done

install_node
install_pm2
install_unzip
if [ -d "super-peer" ];then
  echo "update super-peer"
  wget -N https://cdn.swarmcloud.net/super-peer.zip
  unzip -o super-peer.zip
  pm2 restart super-peer
  if [ $? -eq 0 ]; then
      echo "super-peer restarted"
      pm2 save
  else
      echo "super-peer update failed"
  fi
else
  echo "download super-peer"
  wget https://cdn.swarmcloud.net/super-peer.zip
  unzip super-peer.zip
  cd super-peer
  echo listenPort=$PORT >> .env
  pm2 start index.js -n super-peer
  if [ $? -eq 0 ]; then
      echo "super peer is listening at port $PORT"
      pm2 save
      pm2 startup
  else
    echo "super peer start failed"
  fi
fi

