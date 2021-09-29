import os
import argparse
import re
import datetime
import csv
import idna
from google_trans_new import google_translator

#(^(xn--.+).[^\s](xn--)(\w+)) first ver
#(^(xn--)(.+)\.(xn--)(\w+)) second ver
#(^(xn--)(.[^\s]+)\.(xn--)(\w+)) third ver
#(^(xn--)(.[^\s]+)\.([^\s])(.[^\s]+)) ver 4
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
            #bug in python encoding library so this throws exceptions on certain valid domains so using a module instead
            # i = i.encode('utf-8')
            # i = i.decode('idna')
            x = idna.decode(i[0])
            i.append(x)
            try:
                i+= translate_urls(x)
            except:
                i+= ['Could not Translate','Could not Translate']
            decoded_domains.append(i)

        except:
            exceptions.append(i)
    if exceptions != []:
        print(len(exceptions),'exceptions found')
        for i in exceptions:
            print(i)
    return decoded_domains

def translate_urls(url):
    translator  = google_translator()
    detect_result = translator.detect(url)
    translated_text = translator.translate(url,lang_tgt='en') 
    return [detect_result[1],translated_text] 

    

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
        
    fields = ['IDN','Filename','Decoded IDN','Language','Translation']
    csvwriter = csv.writer(file)
    csvwriter.writerow(fields) 
    csvwriter.writerows(decoded)
    file.close()
    print('Decoded IDNs saved as',filename)
    
    
def main():
    file_names = get_file_paths()
    filtered_domains = filter_domains(file_names)
    decoded = decode_domains(filtered_domains)
    if args.output:
        for i in decoded:
            print(i)
        
    save_file(decoded,args.filename,args.destination)
        
    
    
    

if __name__ == '__main__':
    main()
