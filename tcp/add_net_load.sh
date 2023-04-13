sudo tc qdisc add dev lo root netem loss 10%

# sudo tc qdisc del dev lo root # to stop
