#
# Copyright 2024 Aon plc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import time
import datetime

PREFIXLEN = 20
filesLocation = "C:\\Users\\Administrator\\Desktop\\"

def list_files_with_prefix(directory, prefix):
	file_list = []
	for filename in os.listdir(directory):
		if filename.startswith(prefix):
			file_list.append(filename)
	return file_list

def remove_special(string_list, special_string):
    cleaned_list = []
    for string in string_list:
        if special_string not in string:
            cleaned_list.append(string)
    return cleaned_list

def delete_files_with_prefix(directory, prefix):
    for filename in os.listdir(directory):
        if filename.startswith(prefix):
            file_path = os.path.join(directory, filename)
            os.remove(file_path)

def delete_sccmod_files(directory_path):
    # Get a list of all files in the directory
    file_list = os.listdir(directory_path)
    
    # Loop through all files in the directory
    for file_name in file_list:
        # Check if the file starts with "sccmod-"
        if file_name.startswith("sccmod-"):
            # If it does, delete the file
            os.remove(os.path.join(directory_path, file_name))

def delete_files_starting_with_20_digits(directory_path):
    for filename in os.listdir(directory_path):
        # Check if the filename starts with a 20-digit string
        if len(filename) >= 20 and filename[:20].isdigit():
            # Construct the full file path
            file_path = os.path.join(directory_path, filename)
            # Check if the file is a regular file (not a directory)
            if os.path.isfile(file_path):
                # Delete the file
                os.remove(file_path)
                print(f"\tDeleted file: {file_path}")

def create_done_file(prefix):
    file_name = prefix + "_done.txt"
    with open(file_name, "w") as file:
        pass # write nothing to the file, just create it

def compileItems(diff_items):
    prefix = list(diff_items)[0].split("_____")[0]
    localDualityPath = "C:\\Users\\Administrator\\Source\\Repos\\DUALITY\\DUALITY\\bin\\Debug\\DUALITY.exe"

    scPath = filesLocation + prefix + "_____sc.bin"
    dllList = list_files_with_prefix(filesLocation, prefix)
    dllList = remove_special(dllList, "sc.bin")
    dllList = list(map(lambda x: filesLocation + x, dllList))
    if(len(dllList) < 1):
        print("Something went wrong")
        return

    dllListStr = (' '.join(dllList))

    commandString = localDualityPath + " " + scPath + " " + dllListStr

    process = os.popen(commandString)
    output = process.read()
    print(output)
    create_done_file(prefix)

def check_integer_characters(string):
    first_20_chars = string[:20] # Get the first 20 characters of the string
    for char in first_20_chars:
        if not char.isdigit():
            return False
    return True

# Courtesy of ChatGPT ;)
def check_for_new_items(folder_path, prefix_length, check_interval=30, callback=None):
    last_items = set()
    counter = 0
    deleteCounter = 50
    print("Purging files")
    delete_files_starting_with_20_digits(filesLocation)
    delete_sccmod_files("C:\\Users\\Administrator\\Source\\Repos\\DUALITY\\DUALITY")
    while True:
        counter += 1
        # Get list of all files in the folder with the given prefix
        new_items = set()
        for filename in os.listdir(folder_path):
            if check_integer_characters(filename) and ".original" not in filename and "_done.txt" not in filename:
                new_items.add(filename)

        # Check if there are any new items
        diff_items = new_items - last_items
        if diff_items:
            counter = 0

            print("Found new items, giving some time to finish up uploads...")
            time.sleep(10) # give a bit of extra time in case we caught it mid-download

            new_items = set()
            for filename in os.listdir(folder_path):
                if check_integer_characters(filename) and ".original" not in filename and "_done.txt" not in filename:
                    new_items.add(filename)

            diff_items = new_items - last_items

            print('New items:', diff_items)
            last_items = new_items

            # Execute user-defined callback function, if provided
            if callback:
                callback(diff_items)
        else:
            now = datetime.datetime.now()
            timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
            print("No new items -", timestamp)
        # Wait for the next check interval

        if counter == deleteCounter:
            print("Purging files")
            delete_files_starting_with_20_digits(filesLocation)
            delete_sccmod_files("C:\\Users\\Administrator\\Source\\Repos\\DUALITY\\DUALITY")

        time.sleep(check_interval)


check_for_new_items(filesLocation, PREFIXLEN, 5, compileItems)        
