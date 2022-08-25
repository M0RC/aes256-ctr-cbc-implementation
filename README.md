# Implementation of CTR and CBC modes for AES-256
![](https://raw.githubusercontent.com/M0RC/aes256-ctr-cbc-implementation/main/demo_cbc.gif)

![](https://raw.githubusercontent.com/M0RC/aes256-ctr-cbc-implementation/main/demo_ctr.gif)

## Description
Here is my implementation of CTR and CBC modes for AES-256.

## Run the program
### Install dependencies
```bash
pip3 install -r requirements.txt
```

## Usage
To use CBC Mode:
```bash
python aes-256.py -f <PLAINTEXT_FILE_PATH> --cbc
```

To use CTR Mode:
```bash
python aes-256.py -f <PLAINTEXT_FILE_PATH> --ctr
```

To use CBC and CTR Mode:
```bash
python aes-256.py -f <PLAINTEXT_FILE_PATH> --all
```
