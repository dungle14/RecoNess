#!/bin/bash

# Update package list
sudo apt-get update

# Install or update Nmap and WhatWeb
sudo apt-get install -y nmap whatweb ffuf

# Install or update Python tools with pip
pip install --upgrade arjun dirsearch
