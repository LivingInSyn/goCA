# goCA
A simple CA utility to create CA's and certificates

# samples so far
``` shell
#create a root CA
goCA -create -root -outname="ca" #creates ca.crt and ca.key
#create an intermediate ca signed by the CA created in the last line
goCA -create -int -outname="int" -cacertpath="ca.crt" -cakeypath="ca.key" #creates int.crt and int.key
```