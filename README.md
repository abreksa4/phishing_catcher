Phishing catcher
----------------

Catching malicious phishing domain names using [certstream](https://certstream.calidog.io/) SSL certificates live stream.

![usage](https://i.imgur.com/4BGuXkR.gif)

# Installation

The script should work fine using Python2 or Python3.

You will need the following python packages installed: certstream, tqdm, entropy, termcolor, tld, python_Levenshtein

```sh
pip install -r requirements.txt
```


# Usage

```
$ ./catch_phishing.py
```

# Notes
This fork of the original script has been modified in the following ways:
1. Tags are now included in each "report" of a domain
2. The raw certstream message data, the determined score, the tags, and a timestamp are now written to disk under the 
`./data` directory with the format `pc_{uuid}.{%Y-%m-%d-%H}.log` as newline-delimited JSON documents (where the UUID is 
unique for each run of the script)
3. Merged in various changes and improvements from other community forks

# Example phishing caught

![Paypal Phishing](https://i.imgur.com/AK60EYz.png)

# License
GNU GPLv3
