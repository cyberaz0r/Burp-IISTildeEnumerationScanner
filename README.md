# Burp IIS Tilde Enumeration Scanner
A Burp extension to enumerate all the shortnames in an IIS webserver by exploiting the IIS Tilde Enumeration vulnerability

Based on <a href="https://github.com/irsdl/IIS-ShortName-Scanner">IIS ShortName Scanner</a>

## Features
This extension will add an Active Scanner check for detecting IIS Tilde Enumeration vulnerability and add a new tab in the Burp UI to manually exploit the vulnerability

In the Burp UI tab you can:
* Check if a host is vulnerable without exploiting the vulnerability</li>
* Exploit the vulnerability by enumerating every shortname in an IIS webserver directory
* Configure the parameters used for the scan and customize them in any way you want
* Edit the base request performed (you can add headers, cookies, edit the User Agent, etc)
* Save the scan output to a file
* Create an Intruder Payload Set for guessing complete names from shortnames retrieved from scan results (by using wordlists)

## Screenshots

### Scanner tab (1366x768)
![scanner_tab](https://user-images.githubusercontent.com/35109470/146651512-3a18c9ac-6725-46fa-9c48-a869d4d3f150.png)


### Configuration tab (1366x768)
![config_tab](https://user-images.githubusercontent.com/35109470/146651516-fa33595c-0904-497b-9e28-7591428d5449.png)

## Changelog

* v1.1
  
  Added an Intruder Payload Set Generator for guessing complete names from shortnames retrieved from scan results (by using wordlists)

* v1.0
  
  First release