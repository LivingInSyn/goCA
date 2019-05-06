package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"gopkg.in/ini.v1"
)

func main() {
	//parse options
	createflag := flag.Bool("create", true, "Set the 'create' action")
	//revokeflag := flag.Bool("revoke", false, "The 'revoke' action. Cannot be used with the 'create' flag")
	rootflag := flag.Bool("root", false, "Set if you're working with a root CA")
	intermediateflag := flag.Bool("int", false, "Set if you're working with an intermediate CA")
	cacertpath := flag.String("cacertpath", ".\\", "The path to the CA cert that's signing this cert.")
	cakeypath := flag.String("cakeypath", ".\\", "The path to the CA key that's signing this cert.")
	//clientflag := flag.Bool("client", false, "Set if you're working with an client cert")
	//serverflag := flag.Bool("server", false, "Set if you're working with a server certificate")
	outpath := flag.String("outpath", ".", "The output path for the file")
	outname := flag.String("outname", "", "The root of the output file name")
	//validity
	expireyearflag := flag.Int("expireYears", 10, "number of years the cert will be valid for. Can be negative")
	validyearflag := flag.Int("validyears", 0, "number of years from todays date for the 'NotBefore' value. Can be negative")
	flag.Parse()
	//parse the ini file
	cfg, err := ini.Load("goCA.ini")
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}
	//TODO: validate the output path
	if *outname == "" {
		log.Panic("outname is required")
	}
	//if create a root CA
	if *createflag && *rootflag {
		createCA(cfg, *validyearflag, *expireyearflag, outpath, false, "", "", *outname)
	} else if *createflag && *intermediateflag {
		if *cacertpath == "" {
			log.Panic("cacertpath is required")
		} else if *cakeypath == "" {
			log.Panic("cakeypath is required")
		}
		createCA(cfg, *validyearflag, *expireyearflag, outpath, true, *cacertpath, *cakeypath, *outname)
	}

}

func createCA(configFile *ini.File, validyear, expireyear int, outpath *string, intermediate bool, cacertpath, cakeypath, outname string) {
	//set the INI section name
	sectionname := "CA"
	if intermediate {
		sectionname = "INT"
	}
	//create the cert object
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{configFile.Section(sectionname).Key("Organization").String()},
			Country:       []string{configFile.Section(sectionname).Key("Country").String()},
			Province:      []string{configFile.Section(sectionname).Key("Province").String()},
			Locality:      []string{configFile.Section(sectionname).Key("Locality").String()},
			StreetAddress: []string{configFile.Section(sectionname).Key("StreetAddress").String()},
			PostalCode:    []string{configFile.Section(sectionname).Key("PostalCode").String()},
		},
		NotBefore:             time.Now().AddDate(validyear, 0, 0),
		NotAfter:              time.Now().AddDate(expireyear, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	//if this is an intermediate cert, we need to load the signing CA from the capath
	var signingCA *x509.Certificate
	if intermediate {
		catls, err := tls.LoadX509KeyPair(cacertpath, cakeypath)
		if err != nil {
			log.Panic(err)
		}
		signingCA, err = x509.ParseCertificate(catls.Certificate[0])
		if err != nil {
			panic(err)
		}
	} else {
		signingCA = ca
	}
	//create the public private keypair
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	caB, err := x509.CreateCertificate(rand.Reader, ca, signingCA, pub, priv)
	if err != nil {
		log.Fatal("create ca failed", err)
	}
	//write the ca cert
	certOut, err := os.Create(fmt.Sprintf("%s%s%s%s", *outpath, string(os.PathSeparator), outname, ".crt"))
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caB})
	certOut.Close()
	log.Print("written ca.crt\n")
	//write the ca key
	keyOut, err := os.OpenFile(fmt.Sprintf("%s%s%s%s", *outpath, string(os.PathSeparator), outname, ".key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written ca.key\n")
}
