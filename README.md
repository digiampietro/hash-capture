# Description

**hash-capture** automatically scans nearby WiFi networks,
deauthenticates clients and tries to capture the four way handshake
that can be later used to offline crack passwords with
[hashcat](https://hashcat.net/) or
[aircrack-ng](https://www.aircrack-ng.org/).

This project was inspired by [pwnagotchi](https://pwnagotchi.ai/) and
[hashcatch](https://github.com/staz0t/hashcatch).

I tried to install pwnagotchi on a Raspberry PI 4 running Raspbian but
had difficulties in installing the pre-requisites (mainly TensorFlow)
so I searched a much simpler alternative to capture handshakes only, I
was less interested in other pwnagotchi features, like AI or
*gamification*.

I found the nice simple script
[hashcatch](https://github.com/staz0t/hashcatch) and I adapted his
idea to my needs:

* I rewrote the script in Perl (my preferred scripting language)
* I optimzed the handshake capture speed ignoring access point SSIDs
  without client connections
* I introduced a *fast* mode, to optimize the capture speed when
  driving or walking fast, scanning a single channel at a time
* I added many configurable options through command line switches

# Table of Content

<!-- md-toc-begin -->
* [Description](#description)
* [Table of Content](#table-of-content)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Usage](#usage)
  * [Required arguments](#required-arguments)
  * [Optional arguments](#optional-arguments)
  * [Commands accepted when running](#commands-accepted-when-running)
  * [Information displayed](#information-displayed)
  * [Remarks](#remarks)
* [License](#license)
* [Author](#author)
<!-- md-toc-end -->


# Prerequisites

**hash-capture.pl** executes aircrack-ng commands and requires the
installation of the following components:

* [**aircrack-ng**](https://www.aircrack-ng.org/), the script executes the
  *airodump-ng* and *aireplay-ng* commands
* [**hashcat-utils**](https://github.com/hashcat/hashcat-utils), the
  script executes the *cap2hccapx* command
* **wireless-tools** (tools for manipulating Linux Wireless
  Extensions), the script executes the *iwconfig* command
* **iw** (tool for configuring Linux wireless devices), the script
  executes the *iw* command
* **figlet** (make large character ASCII banners out of ordinary
  text), only needed with the option to print large chars on a
  terminal, useful when the terminal is running on a small mobile
  phone screen
* **libterm-readkey-perl** (perl module for simple terminal control)

Prerequisites can be installed using commands similar to the
followings (in Debian or Ubuntu based distribution):

```
$ # install available packages
$ sudo apt-get install aircrack-ng wireless-tools iw figlet libterm-readkey-perl
$ #
$ # install from source hashcat-utils, cloning from github
$ git clone https://github.com/hashcat/hashcat-utils
$ cd hashcat-utils/src
$ make
$ # install executable in /usr/local/bin, removing the ".bin" extension
$ # assuming /usr/local/bin is in the standard PATH
$ for i in *.bin; do f=`basename $i .bin`; sudo cp $i /usr/local/bin/$f; done
```

# Installation

* Install the prerequisites, see above paragraph
* Clone this repository, with commands similar to
  ```
   $ git clone https://github.com/digiampietro/hash-capture
  ```
* Copy the *hash-capture.pl* script in a directory included in your
  PATH with commands similar to:
  ```
  $ cd hash-capture
  $ sudo cp hash-capture.pl /usr/local/bin/
  ```

# Usage

First you have to Put the wireless interface in monitor mode, usually,
but not allways, this can be achieved with the following command
(assuming your wireless interface, supporting monitor mode, is wlan0)

```
$ sudo airmon-ng start wlan0
```

Execute the hash-capture script with sudo (or as *root*) with the
desired arguments:

```
$ sudo hash-capture.pl -i monitoring-interface [ options ]
```

## Required arguments

* ``-i monitoring-interface`` where *monitoring-interface* is the name
  of the interface in *monitor mode* for example it could be
  *wlan0mon*. This is the only mandatory argument.

## Optional arguments

* ``-s scanTime`` time to scan the WiFi neighborhood before starting
  to de-authenticate connected clients. Default is 10 seconds in *std*
  mode and 5 seconds in *fast* mode.
* ``-c captureTime`` time to capture handshakes after
  de-authenticating users. Default is 10 second in *std* mode and 5
  seconds in *fast* mode.
* ``-n ndeauth`` number of de-authentication packets to send to
  disconnect clients. Default is 5.
* ``-m minPower`` minimum station and access point power (as reported
  by *airodump-ng*) to send de-authentication packets. If the reported
  power is lower than this value, the client is ignored. Default value
  is -90.
* ``-d handshakeDir`` directory where to store handshakes. Default is
  */usr/share/hash-capture*. If this directory doesn't exists it will
  be created. Handshakes are stored in
  */usr/share/hash-capture/handshakes* and the list of successfully
  captured handshakes is stored in the text file
  */usr/share/hash-capture/found.txt*, this text file is read each
  time *hash-capture.pl* starts; Access Points with already captured
  handshakes will be ignored. If you change the directory with this
  option, the original *found.txt* will not be found and already
  captured handshakes will be captured again.
* ``-b`` selects very big font on display, using *figlet*. This can be
  useful when the terminal is running on a small mobile phone screen.
* ``-o std|fast`` selects operation mode, default is *std*. In *std*
  mode *airodump-ng* is used to scan the entire WiFi spectrum; in
  *fast* mode *airodump-ng* will scan only a channel at a time, in a
  shorter time; the channel is randomly chosen but channels 1, 6 and
  11 have a much higher probability than other channels. Usually
  *fast* mode is better when driving or when walking fast.
* ``-v `` verbose, prints, on standard error, a lot of (un)useful
  information. Useful for debugging the script or better understanding
  what the script does.
* ``-h`` prints a short help.
* ``-x`` dont remove temporary files stored in */tmp* directory,
  useful only for debugging.

## Commands accepted when running

When running, the script recognizes the following key presses (case
insensitive):

* ``Q`` quit the program.
* ``S`` switch to *std* mode, after this switch *scanTime* and
  *captureTime* will assume the default values (10 seconds) for the
  *std* mode. The switch will happen after the current capture cycle.
* ``F`` switch fo *fast* mode, after this switch *scanTime* and
  *captureTime* will assume the default values (5 seconds) for the
  *fast* mode. The switch will happen after the current capture cycle.

## Information displayed

An example of information displayed is the following:
```
Mode:       std
Status:     Listening
Subject:    valeriobo0
Found:      1
Sequence:   2 - 1
```

* *Mode* is the operating mode and can be *std* or *fast*.
* *Status* is the current status that can be:
  + *Scanning* scanning the airwaves.
  + *Deauth* sending deauthentication packets to the selected client.
  + *Listening* capturing packets after deauthentication hoping to
    capture a valid handshake.
* *Subject* is the name of the SSID during the *Deauth* and
  *Listening* status. Empty in the *Scanning* status.
* *Found* is the number of new valid handshakes found since the start of
  the program.
* *Sequence* is the current cycle number: the first number is the
  number of each Scan/Deauth/Listening cycle; the second number is the
  number of the current de-authenticating client.

When the *-b* option is selected (big font) the display is slightly
different, but the information is the same, as shown below:
```
Mode:       std
 _      _       _                _
| |    (_) ___ | |_  ___  _ __  (_) _ __    __ _
| |    | |/ __|| __|/ _ \| '_ \ | || '_ \  / _` |
| |___ | |\__ \| |_|  __/| | | || || | | || (_| |
|_____||_||___/ \__|\___||_| |_||_||_| |_| \__, |
                                           |___/
              _              _         _              ___
__   __ __ _ | |  ___  _ __ (_)  ___  | |__    ___   / _ \
\ \ / // _` || | / _ \| '__|| | / _ \ | '_ \  / _ \ | | | |
 \ V /| (_| || ||  __/| |   | || (_) || |_) || (_) || |_| |
  \_/  \__,_||_| \___||_|   |_| \___/ |_.__/  \___/  \___/

 _                                                        ____      _ 
/ |  _ __    ___ __      __          _ __  _   _  _ __   |___ \    / |
| | | '_ \  / _ \\ \ /\ / /  _____  | '__|| | | || '_ \    __) |   | |
| | | | | ||  __/ \ V  V /  |_____| | |   | |_| || | | |  / __/  _ | |
|_| |_| |_| \___|  \_/\_/           |_|    \__,_||_| |_| |_____|(_)|_|

```

## Remarks

This script try to be as efficient as possible to capture as much
handshakes as possible, but it is almost impossible to capture
handshakes when driving because, also in *fast* mode, it take at least
10 seconds to scan, deauth and capture handshakes and if you are
driving at a low speed, for exapmle 40Km/h, you will do more than
100mt in 10 seconds, enough to go out of the access point reach.

In *fast* mode it is easier to capure handshakes when driving in a
city, with houses at the border of the road and stopping frequently in
traffic queues or at traffic lights.

*fast* mode can be useful also when walking the dog, but if your dog
prefers to stop and investigate the surroundings a little longer than
usual, than the *std* mode, with longer scanTime and captureTime, can
be better.

# License

Copyright (c) 2019 Valerio Di Giampietro, distributed with the *MIT
License*, for further details see the [LICENSE](./LICENSE) file

# Author
I am happy to be contacted about this project, my contact details are:

|Item             |Content                                          |
|-----------------|-------------------------------------------------|
|Author's name    |Valerio Di Giampietro                            |
|Email            |v@ler.io (yes it's a valid email address!)       |
|Personal web site|http://va.ler.io (aka http://digiampietro.com)   |
|LinkedIn         |http://it.linkedin.com/in/digiampietro           |
|Twitter          |http://twitter.com/valerio                       |
|Facebook         |http://facebook.com/digiampietro                 |
