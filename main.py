import pandas as pd
import collections
import re
from fuzzywuzzy import fuzz
import itertools
from tqdm import tqdm
import time
import csv
import os

#simple file chooser dialog - for grabbing the file to analyse
import Tkinter,tkFileDialog
root = Tkinter.Tk()
root.withdraw()
filename = tkFileDialog.askopenfile(parent=root,mode='r',filetypes=[("Excel file","*.csv")],title='Choose a csv file')

#define desktop path for later
desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')

#Grab the csv
data = pd.read_csv(filename, sep=',', quotechar='"', encoding='utf8', na_values=[''])
#grab_whitelist csv
wl_data = pd.read_csv(<location of whitelist.csv>, sep=',', quotechar='"', encoding='utf8', na_values=[''])
#grab common words used in malspam lures csv
bad_data = pd.read_csv(<location of bad_lures.csv>, sep=',', quotechar='"', encoding='utf8', na_values=[''])

#Dropping the shite data columns - useless and blank mainly
clean_data = data.drop(['Recipients','Reason','FirstVirusName'], axis=1)
#renaming the columns cause they screw up on the first one and go out of sync - workaround is fine as we aren't arsed about the time column
renamed_data = clean_data.rename(index=str, columns={"UTC Time": "Subject", "Subject": "Sender", "Sender": "Recipient", "SpamScore":"Action", "Processed":"Reason","Disposition":"Processed"})
#recreate the data frame and filter out anything from the whitelist na=false stops comparison when no value exists in the row
df = renamed_data[~renamed_data['Sender'].str.contains('|'.join(wl_data['sender']), na=False)]
#escape regex characters in subjects and write to new list
wl_escape =[]
for i in tqdm(wl_data['subject']):
    wl_escape.append(re.escape(i))
#recreate the data frame and filter out anything from the whitelist_subjects na=false stops comparison when no value exists in the row
df2 = df[~df['Subject'].str.contains('|'.join(wl_escape), na=False)]
# ------ DF2 is the data frame once whitelist entris have been removed (most of the hunting\filtereing should be done on this bad boy

#--- This bit is to check when commonly used lure words are in the string (likely a v high false postive chance as it's just string matching

#grab all the lures and subjects and check if any of them are present - strip out the nan floats from the panda object first
subject = []
lures=[]
#dump the nans - getting rid of these cause they are the blanks but represent as floats and these are not strings oh no they are not, this is the simplest way to crack on with doing string operations on the dat herein
series_df_subject = df2["Subject"].dropna()
#bang all the subjects into a list and deal with python 2.7 unicode issues - encode each string
for i in tqdm(series_df_subject):
    subject.append(i.encode('utf-8'))
#remove duplicates from the subjects
subject_stripped = list(dict.fromkeys(subject))
#check to see if any of the bad words are in the de-duplicated subjects
for i in  tqdm(bad_data['lures']):
    lures.append(i.encode('utf-8'))
subjects_containing_lures = []
for i in subject_stripped:
    if any(word in i for word in lures):
        subjects_containing_lures.append(i)

# Simply returning the top ten subjects once whitelisted elements are removed
subject_counter = collections.Counter(df2["Subject"].dropna())
# Simply returning the top ten senders once whitelisted elements are removed
sender_counter = collections.Counter(df2["Sender"].dropna())


#Check for subjects\senders where wrapped is in the reason column
wrapped_url_df = df2.loc[df2['Processed'].str.contains('url-wrapped', na=False)].dropna()

#grtab a list of subjects senders adn remove duplciate
de_dupe_wrapped_url_senders = list(dict.fromkeys(wrapped_url_df['Sender']))
de_dupe_wrapped_url_subjects = list(dict.fromkeys(wrapped_url_df['Subject']))

#grab a list of subjects senders and count reccurences
wrapped_sender_counter = collections.Counter(wrapped_url_df["Sender"].dropna())
wrapped_subject_counter = collections.Counter(wrapped_url_df["Subject"].dropna())

#This bit bangs through all the subjects and does some fuzzy matching (Levenshtein) then returns a list of subjects that had a match of 70 or more - due to stripping out the whitelisted elements first this can be sued to identify spam subject
subjects_with_similar_subjects = []
for a, b in tqdm(itertools.combinations(de_dupe_wrapped_url_subjects, 2)):
    if fuzz.partial_ratio(a, b) >80:
        subjects_with_similar_subjects.append(a)
#de-dupe the list so we have stuff to go hunt for
many_similar_subjects_stripped = list(dict.fromkeys(subjects_with_similar_subjects))

##/----- Aesthetic shit -----\##
# this shit basically presents it the way it's been requested
#add a title to the key bits of info for writing to the file (tt = top ten, ttw = top ten wrapped(Wrapped subjects = callsification by toolset includes wrapped - wrapped = bad))

wrapped_subjects = ["Subjects where body contains wrapped URL"] + de_dupe_wrapped_url_subjects
lures_in_subject = ["Subjects containing lures of interest"] + subjects_containing_lures
fuzzy_subjects = ["Subjects that have multiple iterations"] + many_similar_subjects_stripped

def pretty_up_the_list(list_that_needs_making_pretty):
    list_that_is_formatted_ooh_so_pretty = []
    for i in list_that_needs_making_pretty:
        list_that_is_formatted_ooh_so_pretty.append(i[0].encode('utf-8')+" , "+str(i[1]))
    return list_that_is_formatted_ooh_so_pretty

tt_subject = ["Top 20 subjects"] + pretty_up_the_list(subject_counter.most_common(20))
tt_sender = ["Top 20 senders"] + pretty_up_the_list(sender_counter.most_common(20))

ttw_subject = ["Top 20 wrapped URL senders"]+ pretty_up_the_list(wrapped_sender_counter.most_common(20))
ttw_sender = ["Top 20 wrapped URL subjects"] + pretty_up_the_list(wrapped_subject_counter.most_common(20))




#printing out all these sweet findings to a file
encode_wrapped = []
for i in wrapped_subjects:
    encode_wrapped.append(i.encode('utf-8'))
fuzzy_wrapped = []
for i in fuzzy_subjects:
    fuzzy_wrapped.append(i.encode('utf-8'))
#grab date time ISO 8601 date format
timestr = time.strftime("%Y%m%d-%Hh_%Mm_%Ss")

#set file name with timestamp
file_save_name_and_timestamp =  timestr+'_hunt_this'


#chuck all the lists into the csv as columns
with open(desktop + "\\" + file_save_name_and_timestamp+".csv", 'w') as f:
    csv.writer(f).writerows(itertools.izip_longest(tt_subject,tt_sender,fuzzy_wrapped,encode_wrapped,ttw_subject,ttw_sender,lures_in_subject))
f.close()
#Loads of white space\blank rows - rewriting the csv into a new one with the space removed
input = open(desktop + "\\" + file_save_name_and_timestamp+".csv", 'rb')
output = open(desktop + "\\" + file_save_name_and_timestamp+"_please.csv", 'wb')
writer = csv.writer(output)
for row in csv.reader(input):
    if any(row):
        writer.writerow(row)
input.close()
output.close()
#lash the original
os.remove(desktop + "\\" + file_save_name_and_timestamp+".csv")
print "Saved it here mate! " + desktop + "\\" + file_save_name_and_timestamp+".csv Go investigate those bad boys! - don't forget to refine my shit show of a whitelist"
