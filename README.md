# QoSimodo
An idea about using netifyd's ndpi engine to classify flows and store a DSCP in firewall connmarks ready for 'act_ctinfo' to pick them up

Realistically this is about me learning sufficient 'c' as I go along whilst trying not to produce excessively spaghetti code and who knows what.


TODO
1) Open/read from socket (this is where netifyd sends its JSON flow data) - never done that before - done
2) Link a json library - json-c in this case - never done that before - done
3) Learn to use said library to extract flow meta data - in progress
4) Extract IP & port numbers
5) Lookup conntrack entry based on those IP & ports
6) Update conntrack entry
7) Come up with some way of configuring rules for the darn thing.
8) Accept some command line parameters (getopt?)
