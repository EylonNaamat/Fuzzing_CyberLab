from scapy.all import *
import time
import sys


counter_invalid = 0 # counts the number of times i have got "invalid ssh identification string."
counter_authentication = 0 # counts the number of times i have got packets with ip length of 104
count_overload = 0 # counts the number of times i got raw load of the same char consecutively
count_length = 0 # count the number of times i got packets with ip length of over than 200
count_rn = 0 # count the number of times we got a packet that its raw load doesnt end with /r/n

first_try_invalid = 0 # start time of the first time i got "invalid ssh identification string."
first_try_authentication = 0 # start time of the first time i got packets with ip length of 104
first_try_overload = 0 # start time of the first time i got packets with the same char consecutively
first_try_length = 0 # start time of the first time i got packets with ip length of over 200
first_try_rn = 0 # start time of the first time i got packets with raw load that dont end with /r/n

tic_invalid = 0 # start time of the fifth time i got "invalid ssh identification string."
tic_authentication = 0 # start time of the fifth time i got packets with ip length of 104
tic_overload = 0 # start time of the fifth time i got packets with the same char consecutively
tic_length = 0 # start time of the fifth time i got packets with ip length of over 200
tic_rn = 0 # start time of the fifth time i got packets with raw load that dont end with /r/n

interface_name = input("Enter The Interface You Want To Sniff Packets From\n")

while 1:
    # sniffing ssh packets
    packet = sniff(iface=interface_name, filter = "tcp and port 22", count = 1)
    # packet[0].show()

    # if there is a raw layer
    if Raw in packet[0]:
        try:
            # get the load
            load = packet[0][Raw].load.decode()
            # checking if we got "Invalid SSH identification string." messages
            if load == "Invalid SSH identification string.":
                counter_invalid += 1

            # checking if we got a packet that its raw load dont end with \r\n
            if load[-1] != '\n' and load[-2] != '\r':
                count_rn += 1

            # checking if we got a packet with the same char consecutively
            i = 0
            flag = False
            while i < len(load):
                count_same_chars = 1
                while (i+1 < len(load)) and (load[i+1] == load[i]):
                    count_same_chars += 1
                    if count_same_chars >= 10:
                        count_overload += 1
                        flag = True
                        break
                    i += 1
                if flag:
                    break
                i += 1
        except Exception as e:
            pass

    # check if we got packets with ip length of over than 200
    if packet[0][1].len >= 200:
        count_length += 1

    # check if we got packets of ip length of 104
    if packet[0][1].len == 104:
        counter_authentication += 1

    # start timer
    if counter_invalid == 1:
        first_try_invalid = time.perf_counter()

    # start timer
    if counter_authentication == 1:
        first_try_authentication = time.perf_counter()

    # start timer
    if count_overload == 1:
        first_try_overload = time.perf_counter()

    # start timer
    if count_length == 1:
        first_try_length = time.perf_counter()

    # start timer
    if count_rn == 1:
        first_try_rn = time.perf_counter()

    # if we got more than 5 packets with "invalid ssh identification string." message in less than a minute - fuzzing detected
    if counter_invalid >= 5:
        tic_invalid = time.perf_counter()
        if tic_invalid - first_try_invalid <= 60:
            print("Fuzzing detected")
            sys.exit()
        counter_invalid = 0

    # if we got more than 5 packets with ip length of 104 in less than a minute - fuzzing detected
    if counter_authentication >= 5:
        tic = time.perf_counter()
        if tic - first_try_authentication <= 60:
            print("Fuzzing detected")
            sys.exit()
        counter_authentication = 0

    # if we got more than 5 packets with ip length of over 200 in less than a minute - fuzzing detected
    if count_overload >= 5:
        tic_overload = time.perf_counter()
        if tic_overload - first_try_overload <= 60:
            print("Fuzzing detected")
            sys.exit()

    # if we got more than 5 packets with the same char consecutively in less than a minute - fuzzing detected
    if count_length >= 5:
        tic_length = time.perf_counter()
        if tic_length - first_try_length <= 60:
            print("Fuzzing detected")
            sys.exit()

    # if we got more than 5 packets that its raw load dont end with \r\n - fuzzing detected
    if count_rn >= 5:
        tic_rn = time.perf_counter()
        if tic_rn - first_try_rn <= 60:
            print("Fuzzing detected")
            sys.exit()

