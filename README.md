# forcepoint_email_hunt
simple script to parse through Forcepoint security portal email tracking results

Run it from windows or adapt paths accordingly

download the requirements

fill in the whitelist and the bad lures file  - point the program to their location

drop a days worth of accepted emails tracking_results

this script bodges through it and prints out a csv of email subjects and senders that are worthwhile looking into

lures csv should be a single column\list of bad words to match (this is dead basic and returns any match so can catch words containing the searched for word so don't be surprised if you turn up scunthorpe or essex)

whitelist should be two columns\ lists  give it a header sender, subject  then chuck in a load of sending domains\addresses and subjects that you don't mind. For now add the same amount of both. if you have extra subjects chuck a load of example.com domains in or a trusted domain. 
