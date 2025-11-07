this is for the Cybersecurity Club in IAU :>

its an automation python file for HTB Machine "Editor" For the Cybersecurity Club in IAU, just the best university in CyS :>

- don't forget to add the host DNS
echo "10.10.15.20 editor.htb" | sudo tee -a /etc/hosts
Connect to HTB openvpn

after using CVE-2025-24893 to get a shell and explore the server file to find /home/Oliver and
cat /usr/lib/xwiki/WEB-INF/hibernate.cfg.xml | grep password
to get  Username=Oliver and Password=theEd1t0rTeam99

it will first log in to a SSH to a valid user in the webserver
and retrieve the USER_FLAG

and it will exploit a Netdata Vulnerability "ndsudo" found after running

CVE-2024-32019


and will get us ROOT Privilege to then navigate to root directory and get the root flag.
