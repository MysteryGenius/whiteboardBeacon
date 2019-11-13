#!/usr/bin/env python3
import re
import os
import signal
import subprocess
import sys
import time
from pprint import pprint
from enum import Enum
from random import randint

# The default uid
defaultUid = "01234567890123456789012345678901"

schemes = [
        "http://www.",
        "https://www.",
        "http://",
        "https://",
        ]


class Eddystone(Enum):
    """Enumerator for Eddystone URL."""

    uid = 0x00
    url = 0x10
    tlm = 0x20


extensions = [
        ".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
        ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov",
        ]

foundPackets = set()

def verboseOutput(text=""):
    """Verbose output logger."""
    sys.stderr.write(text + "\n")

def encodeUid(uid):
    """UID Encoder."""
    if not uidIsValid(uid):
        raise ValueError("Invalid uid. Please specify a valid 16-byte (e.g 32 hex digits) hex string")
    ret = []
    for i in range(0, len(uid), 2):
        ret.append(int(uid[i:i+2], 16))
    ret.append(0x00)
    ret.append(0x00)
    return ret

def uidIsValid(uid):
    """UID Validation."""
    if len(uid) == 32:
        try:
            int(uid, 16)
            return True
        except ValueError:
            return False
    else:
        return False

def encodeMessage(data, beacon_type=Eddystone.url):
    """Message encoder."""
    if beacon_type == Eddystone.url:
        payload = encodeurl(data)
    elif beacon_type == Eddystone.uid:
        payload = encodeUid(data)
    encodedmessageLength = len(payload)

    verboseOutput("Encoded message length: " + str(encodedmessageLength))

    if encodedmessageLength > 18:
        raise Exception("Encoded url too long (max 18 bytes)")

    message = [
            0x02,   # Flags length
            0x01,   # Flags data type value
            0x1a,   # Flags data

            0x03,   # Service UUID length
            0x03,   # Service UUID data type value
            0xaa,   # 16-bit Eddystone UUID
            0xfe,   # 16-bit Eddystone UUID

            5 + len(payload),  # Service Data length
            0x16,   # Service Data data type value
            0xaa,   # 16-bit Eddystone UUID
            0xfe,   # 16-bit Eddystone UUID

            beacon_type.value,   # Eddystone-url frame type
            0xed,   # txpower
            ]

    message += payload

    return message


def advertise(ad, beacon_type=Eddystone.url):
    """Advertise an eddystone URL."""
    print("Advertising: {} : {}".format(beacon_type.name, ad))
    message = encodeMessage(ad, beacon_type)

    # Prepend the length of the whole message
    message.insert(0, len(message))

    # Pad message to 32 bytes for hcitool
    while len(message) < 32:
        message.append(0x00)

    # Make a list of hex strings from the list of numbers
    message = map(lambda x: "%02x" % x, message)

    # Concatenate all the hex strings, separated by spaces
    message = " ".join(message)
    verboseOutput("Message: " + message)

    subprocess.call("sudo hciconfig hci0 up",
                    shell=True, stdout=DEVNULL)

    # Stop advertising
    subprocess.call("sudo hcitool -i hci0 cmd 0x08 0x000a 00",
                    shell=True, stdout=DEVNULL)

    # Set message
    subprocess.call("sudo hcitool -i hci0 cmd 0x08 0x0008 " + message,
                    shell=True, stdout=DEVNULL)

    # Resume advertising
    subprocess.call("sudo hcitool -i hci0 cmd 0x08 0x000a 01",
                    shell=True, stdout=DEVNULL)

def stopAdvertising():
    """Stop advertising."""
    print("Stopping advertising")
    subprocess.call("sudo hcitool -i hci0 cmd 0x08 0x000a 00",
                    shell=True, stdout=DEVNULL)

def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

def main():
    # try:
    #     while True:
    #         code = hex(str(random_with_N_digits(8)) + "000000000000000000000000")
    #         advertise(code, Eddystone.uid)
    #         time.sleep(5000)
    # except KeyboardInterrupt:
    #     stopAdvertising()
        code = str(random_with_N_digits(8)) + "000000000000000000000000"
        print(code)
    


if __name__ == "__main__":
    main() 
