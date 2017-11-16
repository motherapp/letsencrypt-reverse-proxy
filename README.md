# Reverse proxy with HTTPS trough lets encrypt

The `/tmp` volume should be mounted for storing the certificates to keep under Lets encrypts ratelimit. If not set new certificates will be created at each new setup of the docker container

## Required enviroment variables
Set `DOMAINS` variable to a comma separated list of domains that points to this server and you want to integrate
Set `PROXY_TO_URL` variable to a comma separated list of proxy urls you want the corresponding domain to point to

IE DOMAINS[i] will point to PROXY_TO_URL[i]

## optional Envs
Set `PORT` To the SSL port you want to listen to default is 443
Set `DOMAIN_CONTACT_EMAIL` to the address you want info about your SSL certificate to


