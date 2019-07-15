# SSH Tunneling

### Local Port Forwarding
Run command on attacker machine
Connect to `127.0.0.1:<local port to listen>` as if you were connecting to `<target host>:<target port>` directly
```
ssh <gateway> -p <ssh port> -L <attacker local port to listen>:<target host>:<target port>
```

### Remote Port Forwarding
Run command on victim machine.
Connect to `<ssh server>:<remote port to bind>` as if you were connecting to `<target host>:<target port>` directly
```
ssh <gateway> -p <ssh port> -R <remote port to bind>:<target host>:<target port>
```

### Dynamic Port Forwarding
Sets up a local SOCKS proxy on `<local proxy port>` that will forward all traffic on this port to its destination through the gateway machine
```
ssh -D <local proxy port> -p <ssh port> <gateway>
```

### Notes
1. `<gateway>` = `<user>@<host>`
2. precede bind port with a colon to listen on 0.0.0.0 instead of 127.0.0.1 (may have to update `GatewayPorts` setting to `yes` in `/etc/ssh/sshd_config` to listen on 0.0.0.0). For example: `ssh -D :9999 root@localhost`

# Proxychains
Can be used with *Dynamic Port Forwarding* (above)
Once a SOCKS proxy has been established, configure proxychains by updating one of the below files (searched for in this order, first one found will be used)
```
./proxychains.conf
$(HOME)/.proxychains/proxychains.conf
/etc/proxychains.conf
```
See config syntax in `/etc/proxychains.conf`
Once configured, any network application can be passed through the SOCKS proxy, as in the following example
```
proxychains nmap -sT -Pn 10.1.1.0/24
``` 

