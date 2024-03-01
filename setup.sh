
sudo apt update
sudo apt install python3 python3-pip net-tools python-is-python3
pip install pipreqs pyflakes
pip install -r requirements.txt

echo "export PATH=$PATH:/home/ubuntu/.local/bin" >> ~/.bashrc
source ~/.bashrc

