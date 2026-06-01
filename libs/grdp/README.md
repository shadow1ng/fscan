# Golang Remote Desktop Protocol

grdp is a pure Golang implementation of the Microsoft RDP (Remote Desktop Protocol) protocol (**client side authorization only**).

Forked from [icodeface/grdp](https://github.com/icodeface/grdp)

## Status

**The project is under development and not finished yet.**

* [x] Standard RDP Authentication
* [x] SSL Authentication
* [x] NTLMv2 Authentication
* [x] Windows Clipboard
* [ ] RDP Client(ugly)
* [ ] VNC Client(unfinished)

## Example

1. build in example dir on linux or windows
2. start example on port 8088
3. http://localhost:8088

## Take ideas from

* [rdpy](https://github.com/citronneur/rdpy)
* [node-rdpjs](https://github.com/citronneur/node-rdpjs)
* [gordp](https://github.com/Madnikulin50/gordp)
* [ncrack_rdp](https://github.com/nmap/ncrack/blob/master/modules/ncrack_rdp.cc)
* [webRDP](https://github.com/Chorder/webRDP)