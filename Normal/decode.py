import os
import argparse
import re
import datetime
import csv
import idna



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
    
#Filter out the IDNs    
def filter_domains(file_names):
    all_domains = []
    for file_name in file_names:
        file =  open(file_name)
        domains = file.readlines()
        for i in domains:
            #include all extensions(idn,filename,converted)
            regex = re.compile('(^(xn--)(.[^\s]+)\.([^\s])(.[^\s]+))')
            match = regex.match(i)
            if match:
                all_domains.append([match.group(1),file_name])
            else:
                pass
        file.close()
        

    return all_domains

#Decode the IDNs into unicode
def decode_domains(domains):
    decoded_domains = []
    exceptions = []
    for i in domains:
        try:
            
            x = idna.decode(i[0])
            i.append(x)
            
            decoded_domains.append(i)

        except:
            exceptions.append(i)
    
    return decoded_domains


    

def save_file(decoded,filename=None,destination=None):
    x = datetime.datetime.now()
    if filename == None:
        filename ='UNICODE_'+ x.strftime("%Y%m%d%H%M%S")+'.csv'#add timestamp
    else:
        filename = filename+'.csv'
    
    if destination != None:
        filename = os.path.join(destination,filename)
    try:

        file = open(filename,'w',newline='',encoding='utf-8')
    except:
        print('Invalid File path')
        
    fields = ['IDN','Filename','Decoded IDN']
    csvwriter = csv.writer(file)
    csvwriter.writerow(fields) 
    csvwriter.writerows(decoded)
    file.close()
    print('Decoded IDNs saved as',filename)
    
    
def main():
    print('Reading filepaths')
    file_names = get_file_paths()
    print('Filepaths read')
    print('Filtering Domains')
    filtered_domains = filter_domains(file_names)
    print('Domains filtered')
    print('Decoding domains')
    decoded = decode_domains(filtered_domains)
    print('Domains decoded')
    if args.output:
        for i in decoded:
            print(i)
    print('Saving to file')
    save_file(decoded,args.filename,args.destination)
        
    
    
    

if __name__ == '__main__':
    print(datetime.datetime.now())
    main()
    print(datetime.datetime.now())
