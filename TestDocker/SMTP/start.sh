#!/bin/bash
service postfix start
tail -f /var/log/mail.log