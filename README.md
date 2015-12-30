#0hw311
<pre>
         (   )                                             (   ) 
   .-.    | | .-.    ___  ___  ___    .--.    .--.   .--.   | |  
 /    \   | |/   \  (   )(   )(   ) /     \  (_  |  (_  |   | |  
|  .-. ;  |  .-. .   | |  | |  | | (___)`. |   | |    | |   | |  
| |  | |  | |  | |   | |  | |  | |    .-. /    | |    | |   | |  
| |  | |  | |  | |   | |  | |  | |    .. \     | |    | |   | |  
| |  | |  | |  | |   | |  | |  | |  ___ \ .    | |    | |   | |  
| .  | |  | |  | |   | |  ; .  | | (   ) ; |   | |    | |   |_|  
.  `-. /  | |  | |   . `-.   `-. .  \ `-.  /   | |    | |   .-.  
 `.__,.  (___)(___)   ..__...__..    .,__..   (___)  (___) (   )  

#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@ 
</pre>
* Shell script to scrape, enumerate, or otherwise rape *nux systems.
* <Written by Darkerego, GPL 2016> <https://github.com/darkerego>
* Based off of g0tmi1k.s excellent writeup on priv escalation:
   https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/



Env Scraper for Linux Post Exploitation

Scraping *nux

Thanks to g0tmilk for saving me a lot of work:
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

Expanded project from bashrecon:
https://github.com/netrecon

# USAGE: $0 <options>
              -s|--scrape : Scrape the system. This will gather as much 
                            information as permissions allow. Caution:
                            this may attract attention if you are on a 
                            pentest.
              -p|--pty    : Try a variety of methods to upgrade to a pty
                            terminal (If you don.t already have one) 
              -d|--dump   : Attempt packet capture through tcpdump. This
                            usually requires root/sudo. Never know, though!
              -h|--help   : Show this help.
