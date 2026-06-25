K1=192.168.122.100
K2=192.168.122.198
K3=192.168.122.53
ONPREM=192.168.122.233
KEY=/root/dezhan/vm/keys/id_ed25519
SSHO="-i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=8"
ssh_n(){ ssh $SSHO dev@"$1" "$2"; }
