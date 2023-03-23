# Fuzzing_CyberLab
## Research
in this task we were asked to write a script that would detect ssh attacks. in order to write this script, i made a reasearch about ssh attacks.
i opened up a new virtual machine and created an internal network with the machine i want to attack.
in the attacking machine i inserted the command "ssh "name of virtual machine"@"the ip of that machine"".
when i tried to get access to the machine i wanted, i have noticed that when i typed the right password i captured a packet with ip length of 680, and when i typed the wrong password i captured a packet with ip length of 104.
so the first thing i did in the code was to capture packets and if i captured more than 5 packets with ip length of 104 - fuzzing detected.
the next thing i did was to open kali linux and trying to attack my machine using metasploit. i have noticed that i got some packets that had raw load of "Invalid SSH identification string." and after some research, i found out it means that its an ssh server's message meaning that the identification didnt make it.
so, if i got more than 5 packets containing this message - fuzzing detected.
moreover, looking into the packets i captured from the kali linux attack, i have noticed that some contained the raw load of a string that has a sequence of the same char consecutively.
so if i got more than 5 of those - fuzzing detected.
</br>
in conclusion, after making some research i created a script to detect ssh attack using the information mentioned above.


## How To Run The Program
in order to run my program the first thing you need to do is to install scapy using the next command.
open the terminal and insert "python3 -m pip install scapy".
next thing you need to do is to insert the interface you want to sniff packets from.
to run the program, go into the projects folder and write "sudo python3 fuzzing.py".


