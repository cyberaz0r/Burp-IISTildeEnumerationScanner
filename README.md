# Burp IIS Tilde Enumeration Scanner
A Burp extension to check for the IIS Tilde Enumeration/IIS short name (8.3) disclosure vulnerability and to exploit it by enumerating all the short names in an IIS web server

Based on <a href="https://github.com/irsdl/IIS-ShortName-Scanner">IIS ShortName Scanner</a>

## Features
This extension will add an Active Scanner check for detecting IIS Tilde Enumeration vulnerability and add a new tab in the Burp UI to manually check and exploit the vulnerability

In the Burp UI tab you can:
* Check if a host is vulnerable without exploiting the vulnerability
* Exploit the vulnerability by enumerating every 8.3 short name in an IIS web server directory
* Configure the parameters used for the scan and customize them in any way you want
* Edit the base request performed (you can add headers, cookies, edit the User Agent, etc)
* Save the scan output to a file
* Create an Intruder Payload Set for guessing complete names from short names retrieved from scan results by using sitemap URLs or dedicated user-provided wordlists

## Screenshots

### Scanner tab (1920x1080)
![1](https://user-images.githubusercontent.com/35109470/148612099-280700ba-db64-4f2e-bcfa-3df83c393bb2.png)


### Configuration tab (1920x1080)
![2](https://user-images.githubusercontent.com/35109470/148612152-8dee95ef-418c-4a99-b73f-8f07d5c04b61.png)

## Changelog
* V2.0
  * Completely refactored code (ate all the spaghetti, now it is fine ;) )
  * Upgraded threading system to a completely new and improved version to address threading-related bugs such as bruteforce running after stopping and issues with the scan/stop button not starting or stopping the scan correctly
  * Adjusted default configuration values and some active scan parameters to improve accuracy of detection
  * Enhanced dynamic values cleaning by utilizing double-request strip in detection mode to reduce false positive ratio and by incorporating more regexes in bruteforce mode to improve bruteforcing accuracy
  * Added dynamic content strip level configuration value to select level of dynamic content stripping with additional regexes
  * Added delay between requests configuration value to specify the delay between request in milliseconds
  * Added Intruder Payload Set Generator to guess complete file names from scan results using sitemap URLs
  * Improved match list building on complete filename guessing
  * Improved name and extension prefixes feature and fixed some bugs on it
  * Fixed duplicates with unfinished extension in results display
  * Fixed some syncronization issues with output and better UI handling on starting/stopping scan
  * Fixed wordlist fields height in UI
  * Fixed some typos and rephrased some parts
  * Changed detection confidence to "Firm" (there can be false positives, it is never certain!)
  * Changed issue references to the original research paper for issue background and Microsoft workaround for remediation background

* v1.1
  
  Added an Intruder Payload Set Generator for guessing complete names from short names retrieved from scan results (by using wordlists)

* v1.0
  
  First release