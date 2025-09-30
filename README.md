# Federation Bank Simulator

A simulated crypto/banking app for fun and learning.

Partly vide-coded, partly hand coded.

This is only for fun. Made for the learners in Oklahoma.

## Install/Prerequisites

Gotta install flask and flask_sqlalchemy: `pip install flask flask_sqlalchemy`

In Arch linux: `pacman -S python-flask python-flask-sqlalchemy`

## How to use

Run the script like any other python script: `python3 fedbankapp.py`

This computer will act as a web server, and it can be accessed by any other computer on the local network.

Open a browser and visit `http://<ip-of-server>:5000` to use the app.

> For example: `http://192.168.1.100:5000`

## Admin Panel

To log into the admin panel the first time, use the username: `admin` and password: `admin`. 
I suggest changing this right away so clever learners don't get admin access.

In the admin panel you can create new users, activate/deactivate users, change user passwords, and mint FCR. 
The admin account also has a wallet address and can transact in FCR to simulate a government supply or the "banker".

## Normal Users

Normal users can create a new account on thier own, or have one created by the admin on their behalf. 
A username and password is required to create a new account, and a wallet address is automatically generated and assigned to the account. 

## Transacting

Any active account can transact with any other active account. A user must simply enter the wallet address of another user, select the amount they wish to transfer, 
and hit the "Send" button. 

## Public Ledger

Any user can click on the "Transactions" button at the top of the app and view all transactions that have taken place.

## Version Log
### v1.0
Initial release
