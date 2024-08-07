## Server VM login (same for all):

> username: **root**
> 

> password: **password**
> 

for SSH, use username: **debian** with password: **debian**

**! dont use the same login twice: for eg if you login as root into the vm, then login as debian when connecting to ssh !**

for the attackers VM, first ensure that the mac adress is different for each VM, then execute ***‘ip a’*** to get the IP. then we can connect with ssh:

```jsx
ssh debian@192.168.64.4
```

install pip on the VM:

```bash
sudo apt install python3-pip -y
```

install libraries:

```bash
pip3 install aiohttp
```

script path: ***/home/debian/attacker.py***

scp [attackers.py](http://attackers.py/) [debian@192.168.64.4](mailto:debian@192.168.64.4):/home/debian

cd /home/debian 

cmd: python3 [attackers.py](http://attackers.py/) 192.168.64.1 3333 10 0.1

python3 <file> <IP> <port> <n_threads> <timeout>