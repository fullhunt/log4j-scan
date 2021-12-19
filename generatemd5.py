import argparse
import hashlib

parser = argparse.ArgumentParser()

parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("-f", "--payloadmd5",
                    dest="payloadmd5",
                    help="Writes out the MD5 from a given payload",
                    action='store')

args = parser.parse_args()

def main():
    if args.usedlist:
        d = open(args.payloadmd5, "w+")
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                d.write(str(i) + ',' + hashlib.md5(i.encode('utf-8')).hexdigest() + '\n')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)