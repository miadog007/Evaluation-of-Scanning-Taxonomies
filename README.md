Evaluation of Scanning Taxonomies
=============

Welcome aboard. This project evaluates Network Scanning Taxonomies for contribution to the greater good. Everyone is welcome to contribute. The project serves as the artifact delivery for the bachelor's thesis "An Evaluation of Scanning Taxonomies Against IBR Traffic".


Project Description 
---------------
Each folder represents a Python version of a Network Scanning Taxonomy. The scripts are based on the original research from the authors in the folder name. The scripts are not a perfect representation of the taxonomies of which they are based, but data processing shows similar results.

The two taxonomies created for the bachelor's thesis are:

- Barnett, R. J. and Irwin, B. (2008)
- Liu, J. and Fukuda, K. (2018)

Both scripts use Python and Dpkt for fast packet capture parsing. 500MB of packet captures takes about 15-20 minutes to be analyzed.

Instructions
---------------
1. Clone repository
2. Open main.py for the wanted taxonomy
3. Add Packet Capture files (PCAP) to 'pcap' variable
4. Run script in Python

For better analyzing purposes, all dicts are created in the main.py. Print out the dicts that interest you!
