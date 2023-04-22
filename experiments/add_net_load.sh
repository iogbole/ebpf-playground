sudo tc qdisc add dev lo root netem loss 10% # to start

# sudo tc qdisc del dev lo root # to stop
