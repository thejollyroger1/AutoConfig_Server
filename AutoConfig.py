#/usr/bin/python
#This script is a WIP and is just something I use to update the system, setup SSH keys and ports and a bit of security in addition to configuring my user.

import subprocess
import sys
import os
import platform
import time
import fileinput
import string
import random

app_list_cent = {}
app_list_debian = {}
operating_system_list = ("debian", "ubuntu", "redhat", "centos")
operating_system = platform.linux_distribution(full_distribution_name=0)[0]
operating_system_version = platform.linux_distribution()[1]
operating_system_version_simple = operating_system_version.split('.')[0]

def update_os():
    #Checking the operating system
    if operating_system not in operating_system_list:
        print "This is not a supported Operating System"
        sys.exit()
    else:
        print "This is a supported operating system, your operating system is " + str(operating_system)
        time.sleep(5)
        print '\n'"Proceeding to update your operating system"
        time.sleep(3)

    #Updating the operating system based on Debian or Redhat
    if operating_system in ("debian", "ubuntu"):
        p1 = subprocess.Popen(["apt-get", "update", "-y"])
        p1.wait()
        p2 = subprocess.Popen(["apt-get", "upgrade", "-y"])
        p2.wait()
        print "Successfully Updated"
    if operating_system in ("redhat", "centos"):
        p1 = subprocess.Popen(["yum", "update", "-y"])
        p1.wait()
        print "Successfully Updated"

#Will install the following applications provided from the list above.
def install_apps():
    if operating_system in ("centos", "redhat"):
        for app in app_list_cent:
            install = subprocess.Popen(["yum", "install", "-y", app])

    elif operating_system in ("ubuntu", "debian"):
        for app in app_list_debian:
            install = subprocess.Popen(["apt-get", "install", "-y", app])

def change_ssh_port():
    #OS check
    tempFile = open("/etc/ssh/sshd_config", 'r+')
    if operating_system not in operating_system_list:
        print "This is not a supported Operating System"
        sys.exit()
    else:
        print '\n'"Changing the SSH listening port to 2222"
        time.sleep(3)

    #SSH daemon restart for Ubuntu and Debian. Made separate if statements for Debian and Ubuntu in case on needs to be changed specifically.
    if operating_system in ("ubuntu", "debian"):
        for line in fileinput.input("/etc/ssh/sshd_config"):
            tempFile.write( line.replace( "port 22", "port 2222" ))
        tempFile.close()
        if operating_system == "ubuntu":
            ubuntu_restartssh = subprocess.Popen(["service", "ssh", "restart"])
            ubuntu_restartssh.wait()
            print "SSH port updated and SSH daemon reset successfully for " + str(operating_system)
        if operating_system == "debian":
            debian_restartssh = subprocess.Popen(["service", "ssh", "restart"])
            debian_restartssh.wait()
            print "SSH port updated and SSH daemon reset successfully for " + str(operating_system)
    elif operating_system in ("centos", "redhat"):
        for line in fileinput.input("/etc/ssh/sshd_config"):
            tempFile.write( line.replace( "#Port 22", "port 2222" ))
        tempFile.close()
        centos_restartssh = subprocess.Popen(["service", "sshd", "restart"])
        centos_restartssh.wait()
        print "SSH port updated and SSH daemon reset successfully for " + str(operating_system)


#Adds a linux user with a password created from the password_create function
def add_user():
        #OS check
    if operating_system not in operating_system_list:
        print "This is not a supported Operating System"
        sys.exit()
    else:
        print '\n'"Adding the spistorio user"
        time.sleep(3)

#Password Generation
    length = 15
    chars = string.ascii_letters + string.digits + '!@#$%^&*()'
    random.seed = (os.urandom(1024))
    password = ''.join(random.choice(chars) for i in range(length))

#useradd with password included in command
    if operating_system in ("centos", "redhat"):
        centos_makeuser = subprocess.Popen(["useradd", "spistorio", "--password", password])
        centos_makeuser.wait()
        print "The password generated for user spistorio is : " + str(password)

    elif operating_system in ("ubuntu", "debian"):
        debian_makeuser = subprocess.Popen(["useradd", "spistorio", "-d", "/home/spistorio", "--password", password])
        debian_makeuser.wait()
        print "The password generated for user spistorio is : " + str(password)

#Adds the spistorio user to the sudoers list
def add_sudo():
    sudoer_file = open("/etc/sudoers", 'a+')
    add_sudo_group = subprocess.Popen(["echo", 'spistorio ALL=(ALL:ALL) NOPASSWD:ALL'], stdout=sudoer_file)
    add_sudo_group.wait()

#adds a newly generated ssh key
def add_ssh_key():

#check for .ssh directory and add one if it's not there
    if not os.path.isdir("/home/spistorio/.ssh/"):
        create_ssh_dir = subprocess.Popen(["mkdir", "/home/spistorio/.ssh"])
        create_ssh_dir.wait()
        print "Your .ssh directory was created"

#check for authorized_keys file and add it if it's not there
    if not os.path.isfile("/home/spistorio/.ssh/authorized_keys"):
        create_auth_file = subprocess.Popen(["touch", "/home/spistorio/.ssh/authorized_keys"])
        create_auth_file.wait()
        print "Your authorized_keys file was created"

#Generate ssh key and add pub key to authorized_keys file
    generate_ssh_key = subprocess.Popen(["ssh-keygen", "-f", "/home/spistorio/.ssh/autoconfigkey", "-N", ''])
    generate_ssh_key.wait()
    print '\n'"Please copy the contents of /home/spistorio/.ssh/autoconfigkey as this is your private key"

    authorized_key_file = open("/home/spistorio/.ssh/authorized_keys", 'r+')
    add_key_to_file = subprocess.Popen(["cat", "/home/spistorio/.ssh/autoconfigkey.pub"], stdout=authorized_key_file)
    add_key_to_file.wait()
    print '\n'"Public key copied to authorized_keys file"

def add_firewall_exception():

#Determine whether operating system is CentOS 7 so as to disable firewalld
    if  float(operating_system_version_simple) >= 7 and str(operating_system) == "centos":
        print '\n'"This version of CentOS is running firewallD, this script disables it."
        disable_firewalld = subprocess.Popen(["systemctl", "disable", "firewalld"])
        disable_firewalld.wait()
        stop_firewalld = subprocess.Popen(["service", "firewalld", "stop"])
        stop_firewalld.wait()
        print '\n'"FirewallD successfully disabled"
        

#If Debian/Ubuntu, check for UFW being enabled and disable it
    elif operating_system in ("debian", "ubuntu"):
        print '\n'"Since Debian/Ubuntu commonly run UFW this script will check the status of the program and disable it if need be."
        ufw_status = subprocess.Popen(["ufw", "status"], stdout=subprocess.PIPE)
        ufw_status_return = ufw_status.communicate()[0]
        ufw_split_status = ufw_status_return.split()
        if ufw_split_status[1] == "active":
            ufw_stop_service = subprocess.Popen(["ufw", "disable"])
            ufw_stop_service.wait()
            print '\n'"UFW Successfully disabled"
        else:
            print '\n'"UFW status is not \"active\", no disabling required"

    print '\n'"Adding two IPTables rules, one to accept port 2222 traffic and one to drop the rest for security."
    add_iptable_drop = subprocess.Popen(["iptables", "-I", "INPUT", "-j", "DROP"])
    add_iptable_drop.wait()
    add_iptable_ssh = subprocess.Popen(["iptables", "-I", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "2222", "-j", "ACCEPT"])
    add_iptable_ssh.wait()

if __name__ == "__main__":
    try:
        update_os()
        change_ssh_port()
        add_user()
        add_sudo()
        add_ssh_key()
        add_firewall_exception()
        print '\n'"Successfully finished, yay!"

    except ValueError:
        print "One of the scripts failed, Sorry :("
