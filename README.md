ALTER USER root WITH SUPERUSER;
 create DATABASE DjangoAngular;
 CREATE ROLE root  WITH LOGIN PASSWORD 'djangoangular';
 python manage.py migrate --run-syncdb
 
 
 #Server
 ssh -R 80:localhost:3000 serveo.net
ssh -R 80:localhost:8888 -R 80:localhost:9999 serveo.net
ssh -R incubo:80:localhost:8888 serveo.net
ssh -R incubo.serveo.net:80:localhost:8888 serveo.net
ssh -R 80:localhost:8888 foo@serveo.net
ssh -R 80:localhost:8888 -l foo serveo.net
#user NGROK
brew install ngrok
brew cask install ngrok
#Keep connection Alive
ssh -o ServerAliveInterval=60 -R 80:localhost:8888 serveo.net