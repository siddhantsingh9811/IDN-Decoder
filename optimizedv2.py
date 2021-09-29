import os
import argparse
import re
import datetime
import csv
import idna
import concurrent.futures


#Program Arguments
parser = argparse.ArgumentParser(description='Extract domains from the specified folder, Filter out IDNs and then decode them into Unicode')
parser.add_argument('path', type=str, help='The path to the folder')
parser.add_argument('-o', '--output', action='store_true', help="Shows Output")
parser.add_argument('-f', '--filename', type=str, help="Specify filename")
parser.add_argument('-d', '--destination', type=str, help="Specify the destination folder")

args = parser.parse_args()

#Get all the file paths from the root folder or any subfolders
def get_file_paths(path=args.path):
    file_names = []

    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            file_names.append(os.path.join(root, name))
    
    return file_names

def append_file(file_name,data):
    with open(file_name,'a',newline='',encoding='utf-8') as file:
        csvwriter = csv.writer(file)
        csvwriter.writerows(data)

def do_stuff(file_name):
    all_domains = []

    
    file =  open(file_name)

    with open(file_name) as file:
        for i in file:
            #include all extensions(idn,filename,converted)
            regex = re.compile('(^(xn--)(.[^\s]+)\.([^\s])(.[^\s]+))')
            match = regex.match(i)
            if match:
                #all_domains.append([match.group(1),file_name])
                try:
                    all_domains.append([match.group(1),file_name,idna.decode(match.group(1))])
                except:
                    pass
            else:
                pass
    print('finished decoding',file_name,len(all_domains),'domains found')
    return all_domains


def main():
    filename = ''
    x = datetime.datetime.now()
    if args.filename == None:
        filename ='UNICODE_'+ x.strftime("%Y%m%d%H%M%S")+'.csv'
    else:
        filename = args.filename+'.csv'

    if args.destination != None:
        filename = os.path.join(args.destination,filename)
    else:
        pass

    with open(filename,'a',newline='',encoding='utf-8') as file:
        fields = ['IDN','Filename','Decoded IDN']
        csvwriter = csv.writer(file)
        csvwriter.writerow(fields) 
        print('created',filename)

    print('Reading filepaths')
    file_names = get_file_paths()
    print('Filepaths read')

    print('Decoding Started')

    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = executor.map(do_stuff, file_names)

        for result in results:
            if len(result) > 0:

                with open(filename,'a',newline='',encoding='utf-8') as file:
                    csvwriter = csv.writer(file)
                    csvwriter.writerows(result)
            else:
                pass
        print('All domains written to file')
                




        
    
    
    

if __name__ == '__main__':
    start = datetime.datetime.now()
    main()
    end = datetime.datetime.now()
    print('Duration: ',end-start)