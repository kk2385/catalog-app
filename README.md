# catalog-app
Project for Udacity's FSND program. A catalog app written with Flask.

The Vagrant config is from [this repository supplied by Udacity](https://github.com/udacity/fullstack-nanodegree-vm). 

I ran this project with Vagrant 1.9.2.

## Run this project

Clone this project and start the vm:
```
cd vagrant
vagrant up
vagrant ssh
```

Once you ssh into the vm, go to the project directory:
```
cd /vagrant/catalog/
```

Setup the database:
```
python database_setup.py
```

Then startup the server:
```
python project.py
```

Go to ```localhost:5000``` and examine the web app.
