# Project Omma: User Manual


Welcome to project Omma. The purpose of this project is to see all that is accessible from outside your organisation. Hence the name 'Omma', meaning 'eye' in ancient Greek. In this user manual, you will learn how to setup project Omma on your device, and what settings you may want to change.
The project consists of two parts: domain detection, to search for domains which you are not aware you owned, and domain control, which searches for vulnerabilities on your known domains, checks your certificates and searches for your data on the darkweb. Project Omma does not prevent attacks, but informs you of the vulnerable points in your digital fortress/shack.

To use project Omma, you need access to the following API's and services:
* Brave Search API (has a free tier)
* Shodan API (paid membership or subscription, the tool was made and tested using an academic membership.)
* A remote Git repository (we suggest using a private GitHub repo, GitHub was used to test the project.). (Used to host a file, this file must be accessible to anyone using the correct link.).
* more tools


## Requirements


To use project Omma, you need a device with python 3.13.2 or higher, with the packages specified in requirements.txt.

To use project Omma, you need access to the following API's and services:
* Brave Search API (has a free tier)
* Shodan API (paid membership or subscription, the tool was made and tested using an academic membership.)
* A remote Git repository (preferably GitHub) with your device's public ssh key added to the keys of a collaborator.
* OpenAI API (Not strictly necessary, but advised if you'll use the provided dashboard).


## Omma tools



## Installation


Clone the Omma GitHub repository to the desired location for setup. This project can be setup in any directory. (Should it be necessary, provide the correct permissions.).


### Domain Detection


Clone your own remote Git repository to a different location. In your local repository, create a file with .goggle as extension, which contains the following:

! name: OmmaGoggle
! description: Removes scanned domains and undesirable domains from the search results.
! public: False
! author: [AUTHOR-NAME]
! avatar: [AVATAR-VALUE]

Replace [AUTHOR-NAME] with your name, and avatar with any HEX-color code.
To add filters to the goggle manually, add the following on a new line:

\$discard,site=[DOMAIN]

Replace [DOMAIN] with the domain you want to discard. Yoru may want to add search-engine websites which are used to search for companies and company data, as these are known to produce false positives in the ownership test.
When you've completed the previous steps (adding filters manually is not required, but advised), push the changes to your own remote Git repository.
For more information regarding goggles, and different types of filters for goggles, please refer to the official Brave documentation [here](https://search.brave.com/help/goggles).
If setup properly, the goggle_update.py script will automatically add approved and rejected domains to the goggle, and push these changes to your Git repository.

Create a .env file, and add the values which you can find in example.env. It is important to not share these API-keys with anyone.

In config.toml, change the following settings according how you've set up the project files and directories:

Under filepaths, add your companies-list json file, your unevaluated-list json file and your evaluated-list json file. The latter  of the three should contain an empty json array [], the companies-list json file should look like the provided companies_example.json. In this json, you will add the information for the companies you want Omma to monitor. Note that only shodan-orgnames can be an empty array, if the data for any of the following fields is missing, add a string which will almost certainly not occur on any websites (for example if you have no VAT number, add "-_-_-novat-_-_-" or something similarly complicated as a string):
* Addresses
* Phones
* Domains
* Emails
* Socials
* VAT-number
Of these, only VAT-number is not an array. Make sure to remove the placeholder string if you have at least one value for the arrays.

Back to config.toml, under domaindetection sesearch, add the following values:
goggle-url: the url to the goggle page you are hosting (if you're using github, paste the link to your raw github page).
goggle-dir: the directory in your local repository in which your goggle file resides. This has to be a full path.
goggle-name: the name of your goggole file, for example 'mygoggle.goggle'.
remote-name: the name of your remote git branch.
local-name: the name of your local git branch.

After this, the initial installation process for domain detection is completed, happy eyeing!


### Domain Control


Domain Control requires the Wapiti vulnerability scanner to be installed on your system for comprehensive security scanning.

#### Installing Wapiti

On Ubuntu/Debian systems, install Wapiti using apt:

```bash
sudo apt update
sudo apt install wapiti
```

For other operating systems, please refer to the [official Wapiti documentation](https://wapiti-scanner.github.io/) for installation instructions.

#### Domain Control Configuration

In config.toml, configure the domainControl settings under the `[domaincontrol]` section:

```toml
[domaincontrol]

# Enable or disable Dark Web scanning (Tor, OnionSearch, DeepDarkCTI)
# Set to false to skip memory-intensive Dark Web operations
darkweb-enabled = false

# Enable or disable Wapiti vulnerability scanning
# Set to false for faster scans without vulnerability assessment
wapiti-enabled = true
```

**Configuration Options:**

* **darkweb-enabled**: Controls whether Dark Web scanning is performed during OSINT analysis. Set to `false` to disable memory-intensive Dark Web operations if you don't need this functionality or have limited system resources.

* **wapiti-enabled**: Controls whether Wapiti vulnerability scanning is performed. Set to `true` to enable comprehensive vulnerability assessment, or `false` for faster scans without vulnerability detection.

After configuring these settings, the domainControl component will be ready to perform security scans on your domains.


## Extra Configuration


#### General Settings

Frequencies are used to determine how frequent a scan is made by a tool. This value represents minutes, for example a frequency of 60 means a scan will be made every 60 minutes. We recommend using an integer.
* sesearch-frequency
* shodsearch-frequency
* owner-test-frequency

Steps are used to determine how many records are run per scan. For example a step-value of 5 for sesearch or shodsearch means one scan will search for 5 different companies (in order of the list). A step-value of 5 for owner-test means owner-test will scan 5 unevaluated domains.
* sesearch-step
* shodsearch-step
* owner-test-step

Start-minutes are used to determine how long the program waits before making its initial scan for a tool. For example, a start-minutes of 5 means the tool will be executed for the first time 5 minutes after starting the program. We recommend using a float or an integer.
* sesearch-start-minutes
* shodsearch-start-minutes
* owner-test-start-minutes

Owner-test-immediate indicate whether the owner-tests are executed immediately after a scan by the sesearch and shodsearch tools. If this value is set to true, the frequency, step and start-minutes values will be ignored for the owner_test tool.
* owner-test-immediate

Goggle-update-on indicates whether new (unevaluated) domains get added to the goggle (which is used by the sesearch tool to filter results). Please turn this off when the goggle file exceeds 2MB or 100000 instructions ( 100005 lines), to prevent problems.
* goggle-update-on



#### Script-specific Settings


##### Owner Test Settings

If you are receiving a lot of false positives and/or false negatives, we encourage you to try different values for the following settings:

Threshold for the likelihood score above which a domain is considered to be owned by a company. This value should be a float between 0.0 and 1.0. This value represents a percentage and the likelihood score will never be higher than 1.0.
* likelihood-threshold

Adjust the sensitivity to certain information found on a website. These values should never be negative. The cleaned name means the company name is stripped from common abbreviations, refering to the business types (inc, llc, bv, ab, gmbh, ...). We recommend leaving power unchanged, changing this value will alter the results in an often extreme way.
* full-name-sensitivity
* cleaned-name-sensitivity
* address-sensitivity
* phone-sensitivity
* domain-sensitivity
* email-sensitivity
* social-sensitivity
* vat-sensitivity
* power

A fuzzy match allows for typos, differences in formatting etc. while searching a document for a string. Fuzzy-match tolerance thresholds determine how close the match must be. These values can range from 0 to 100. The low tolerance threshold is used for data where we will be less tolerant. The low-tolerance threshold is used for the company name, the cleaned company name and phone numbers. The high tolerance threshold is used for th addresses (formatting may differ more here.). All other data does not get fuzzy matched (they must be an exact match.).
* low-tolerance-threshold
* high-tolerance-threshold

Window factor will make the window for the fuzzy match bigger. This means we're comparing a bigger part of a document than the data we're searching for. This allows for typos and differences in formatting to be forgiven (for example an extra space, dots in an abbreviation, ...). We recommend leaving this value unchanged.
window-factor = 0.05

Turn sesearch on/off for the evaluation process. If you don't have access to the Brave Search API or limited API calls, turn this off. This might cause more false negatives when turned off (this is used to find webpages which cannot be found through crawling if the webpage is never referenced on other webpages.).
* sesearch-on


## Warnings and General Advice


### Domain Detection


* When using multiple companies, it can occur that a domain which belongs to one of your companies gets found using the information available for one of your other companies. This will probably result in a false negative. Because of this, we recommend manually checking every domain. Should such case occur, we advice you to always manually add the domain to the correct company in your companies-list json file.
* Because of the nature of this tool, false positives and false negatives are bound to occur. It is possible to tweak the sensitivities for certain information and you can change the minimum score threshhold for the owner_test tool, regardless, we still advice you to always manually check all found domains, regardless of their predicted ownership.
* A common false positive are company search tools, because these tools typically contain information about the company you're searching. They may also, regardless of the likelihood score, take a long time to scan due to them containing a lot of pages.


## Running the code


To run project Omma, navigate to the directory in which the master.py script resides, and simply run master.py without any arguments. We advise you to run the code in the background, in order to safely close any terminal.
To run the dashboard, simply run app.py. We encourage you to create your own dashboard in order to integrate project Omma with your other security tools.


## Credits
Domain control made by MoMo-oui
Domain detection & masterscript made by bram1305
