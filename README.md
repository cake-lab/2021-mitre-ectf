# 2021 MITRE eCTF Challenge: Secure Common Embedded Wireless Link (SCEWL)

This repository contains the WPI2/GOATS team's submission for the 2021 MITRE Collegiate eCTF. It is based on the [example reference system](https://github.com/mitre-cyber-academy/2021-ectf-insecure-example) provided by MITRE.

## Project Structure
The code is structured the same as the example code, which is as follows:

* `controller/` - Contains everything to build the SCEWL Bus Controller. See [Controller README](controller/README.md)
* `cpu/` - Contains everything to build the user code of the CPU. See [CPU README](cpu/README.md)
* `dockerfiles/` - Contains all Dockerfiles to build system
* `radio/` - Contains the Radio Waves Emulator
* `socks/` - Directory to hold sockets for the network backend
* `tools/` - Miscellaneous tools to run and interract with deployments
* `Makefile` - Root Makefile to build deployments
