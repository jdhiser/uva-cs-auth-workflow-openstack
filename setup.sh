#!/bin/bash 

sudo apt update
sudo apt install python3 python3-pip net-tools python-is-python3 python3-designateclient python3-neutronclient -y
pip install pipreqs 
pip install -r requirements.txt

echo "export PATH=$PATH:/home/ubuntu/.local/bin" >> ~/.bashrc
source ~/.bashrc

