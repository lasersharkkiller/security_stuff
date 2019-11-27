#! /bin/bash
#CentOS Caldera install
cd /opt
# Set up the Mongo Database. Adding the 4.0 repository to the distro
echo "[mongodb-org-4.0]
name=MongoDB Repository
baseurl='https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/4.0/x86_64/'
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-4.0.asc" > /etc/yum.repos.d/mongodb-org-4.0.repo
#Start install of prereqresiuts 
yum -y install wget yum-utils 
yum -y groupinstall development 
yum -y install https://centos7.iuscommunity.org/ius-release.rpm
yum -y install python36u python36u-pip python36u-devel mongodb-org
pip3.6 install --upgrade pip setuptools
# Clone Caldera and install requirments
git clone https://github.com/mitre/caldera.git
cd /opt/caldera/caldera
pip3.6 install -r requirements.txt
# Establish user and replication for Mongo DB
echo "replication:
   replSetName: caldera" >> /etc/mongod.conf
#Start Mongo DB
systemctl start mongod
#Get the windows client 
mkdir /opt/caldera/dep/
mkdir /opt/caldera/dep/crater/
mkdir /opt/caldera/dep/crater/crater/
cd /opt/caldera/dep/crater/crater/
wget https://github.com/mitre/caldera-crater/releases/download/v0.2.0-beta/CraterMainWin7.exe
mv CraterMainWin7.exe CraterMain.exe
echo "COMPLETE"
# Adding Caldera to /bin
echo "#! /bin/bash
cd /opt/caldera/caldera
python3.6 /opt/caldera/caldera/caldera.py &" > /bin/caldera
chmod +x /bin/caldera
#Adding Caldera to System Startup
echo " [Unit]
Description=Caldera Server

[Service]
Type=oneshot
ExecStart=/bin/caldera
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/caldera.service
#Enable the service to start on startup
systemctl enable caldera.service
#Enable the clients through the firewall
firewall-cmd --zone=public --add-port=8888/tcp --permanent
firewall-cmd --zone=public --add-port=8889/tcp --permanent

#init 6
