# -*- coding: utf-8 -*-
"""
Created on Tue Apr 23 16:01:43 2024

@author: edanc
"""

import re
import sqlite3
import os
import concurrent.futures
import winreg


class DB_File:
    def __init__(self, db_path):
        self.db_path = db_path
        self.connection = sqlite3.connect(self.db_path)
        self.cursor = self.connection.cursor()
    
    # GETS A CONNECTION TO A .db FILE AND CLOSES THE CONNECTION (RETURNS NOTHING)
    def close_db_connection(self):
        self.connection.close()
        return
    
    # GETS FILE PATH, A CONNECTION AND CURSOR TO A .db FILE AND A TABLE NAME (OPPTIONAL)
    # RETURNS sha256 AND md5 HASHES FOR THE FILE PATH FROM THE .db FILE
    def get_hash_from_db(self, file_path, hash_algorithm_str, table_name="hashes"):
        sql_str = "SELECT " + hash_algorithm_str + " FROM " + table_name + " WHERE file_path = ?"
        self.cursor.execute(sql_str, (file_path,))
        
        result = self.cursor.fetchone()
        
        if result:
            return result
        return None
    
    # GETS sha256 AND md5 HASHES AND COMPARES THEM TO THE HASHES IN THE .db FILE
    # RETURNS BOOLEAN: TRUE -> THE HASHES ARE EQUAL | FALSE -> THE HASHES ARE NOT EQUAL
    def is_hashes_equal(self, file_path, current_hash, hash_algorithm_str):
        original_hash = self.get_hash_from_db(file_path, hash_algorithm_str)
        if current_hash != original_hash:
            return False
        return True
    
    # GETS A FILE PATH, 2 HASHES OF THE FILE (sha256, md5), A .db FILE PATH AND A TABLE NAME (optional)
    # ADDS THE FILE PATH AND THE HASHES TO THE DATA BASE, RETURNS None
    def add_hashes_to_db(self, file_path, sha256, md5, db_table="hashes"):
        self.cursor.execute("INSERT OR IGNORE INTO ", db_table, " (file_path, sha256, md5) VALUES (?, ?, ?)"
                          ,(file_path, sha256, md5))
        return None


# GETS A BYTE STRING AND REMOVES WHITESPACE CHARACTERS EXCLUDING SPACE
# RETURNS A BYTE STRING WITHOUT WHITESPACE CHARACTES (EXCLUDING SPACE)
def remove_whitespace_except_space(byte_string):
    print("CLEARING: ", byte_string)
    return bytes(filter(lambda char: char != ord(b' ') and char not in [9, 10, 13], byte_string))

# GETS A STRING AND CHECKS IF IT CONTAINS ONLY WHITE SPACE CHARACTERS
def contains_only_whitespace_characters(string):
    # Define the pattern to match
    pattern = r'^[\s{};]*$'

    # Check if the string matches the pattern
    if re.match(pattern, string):
        return True
    return False

# GETS A STRING AND CHECKS IF IT IS RELEVANT FOR THE ANTI-VIRUS TO SCAN
# RETURNS BOOLEAN. TRUE -> ANTI-VIRUS SCAN | FALSE -> ANTI-VIRUS DON'T SCAN.
def line_is_relevant(line):
    if contains_only_whitespace_characters(line):
        return False
    if "return" in line or "continue" in line:
        return False
    return True    
    

# GETS A BYTE STRING AND REMOVES WHITESPACE CHARACTERS EXCLUDING SPACE
# RETURNS A BYTE STRING WITHOUT THE WHITESPACE CHARACTERS (EXCLUDING SPACE)
def remove_special_characters_byte(byte_string):
    # Define a translation table to remove whitespace characters excluding space
    translation_table = bytes.maketrans(b'\t\n\x0b\x0c\r', b' ' * 5)

    # Use bytes.translate() to remove whitespace characters
    cleaned_bytes = byte_string.translate(translation_table)

    return cleaned_bytes
    
# GETS A LIST OF STRINGS AND REMOVES IRRELEVANT STRINGS FOR THE ANTI-VIRUS TO SCAN
# RETURNS NOTHING
def clear_list_from_irrelevant_lines(l):
    for line in l:
        if not line_is_relevant(line):
            l.remove(line)  
    return

# GETS A FILE PATH | RETURNS THE FILE'S TYPE
def get_file_type(file_path):
    file_type = re.search("(\.)(.+$)", file_path)
    if file_type == None:
        return None
    file_type = file_type.group(2)
    return file_type.lower()
    
# GETS A FILE PATH AND CHECKS IF THE FILE CONTAINS MALICIOUS CODE 
# RETURNS BOOLEAN: TRUE -> MALICIOUS | FALSE -> NOT MALICIOUS
def is_file_contains_malicious_code(file_path, db_file):
    SIMILARITY_PERCENTAGE = 20
    db_file.cursor.execute("SELECT name FROM viruses;")
    viruses_names = db_file.cursor.fetchall()
    file = open(file_path, 'rb')
    file_lines = file.readlines()
    for i in range(len(file_lines)):
        file_lines[i] = remove_whitespace_except_space(file_lines[i])
    file.close()
    for name in viruses_names:
        virus_name = name[0]
        db_file.cursor.execute("SELECT code FROM viruses WHERE name = ?", (virus_name,))
        virus_code = db_file.cursor.fetchall()[0][0]
        virus_code_lines = virus_code.splitlines()
        
        lines_counter = 0

        clear_list_from_irrelevant_lines(virus_code_lines)

        for i in range(len(virus_code_lines)):
            virus_code_lines[i] = virus_code_lines[i].encode("UTF-8")
            
            virus_code_lines[i] = remove_whitespace_except_space(virus_code_lines[i])
            print(virus_code_lines[i])
            print(file_lines[0])
            if virus_code_lines[i] in file_lines:
                lines_counter += 1
            
        virus_percentage_in_file = (lines_counter / len(virus_code_lines)) * 100
        print("PERCENTAGE: ", virus_percentage_in_file)    

        if virus_percentage_in_file >= SIMILARITY_PERCENTAGE:
            db_file.connection.commit()
            db_file.close_db_connection()
            return True
    
    return False



def chunk_generator(content, buffer_size=8192):
    start = 0
    while start < len(content):
        yield content[start : start + buffer_size]
        start += buffer_size

# GETS A FILE PATH | RETURNS THE FILE'S CONTENT
def get_file_content(file_path):
    with open(file_path, 'rb') as f:
        content = b""
        while chunk := f.read(8192): # Read in 8KB chunks
            content += chunk
    return content 

# GETS A FILE'S CONTENT AND A HASH ALGORITHM | RETURNS THE HASH OF THE CONTENT
def calculate_hash(content, hash_algorithm):
    if content is None:
        raise ValueError("File content not loaded. Call open_file() before calculating hash.")
    
    hash_obj = hash_algorithm()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(hash_obj.update, chunk) for chunk in chunk_generator(content)]
        concurrent.futures.wait(futures)  # Wait for all threads to finish
    return hash_obj.hexdigest()



# GETS A FILE PATH AND RETURNS THE FILE SIZE IN KB
def get_file_sizeKB(file_path):
    try:
        # Get the size of the file in bytes
        size_in_bytes = os.path.getsize(file_path)

        # Convert bytes to kilobytes
        size_in_kb = size_in_bytes / 1024

        return size_in_kb
    except FileNotFoundError:
        print(f"The file at {file_path} does not exist.")
        return None


def is_virus_signature_in_file(content, db_file, db_table="virus_signatures"):
    db_file.cursor.execute("SELECT signature FROM " + db_table)
    ret = False
    virus_signatures = db_file.cursor.fetchall()
    
    for signature in virus_signatures:
        virus_signature = str.encode(signature[0])
        if virus_signature in content:
            ret = True
    
    return ret


def snapshot_registry():
    snapshot = {}

    # Root keys in the registry
    root_keys = [winreg.HKEY_CLASSES_ROOT, winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_USERS, winreg.HKEY_CURRENT_CONFIG]

    for root_key in root_keys:
        snapshot[root_key] = {}

        try:
            # Open the root key for reading
            with winreg.OpenKey(root_key, None, 0, winreg.KEY_READ) as key:
                snapshot[root_key]['values'] = {}
                snapshot[root_key]['subkeys'] = []

                # Enumerate the values under the key
                index = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, index)
                        snapshot[root_key]['values'][value_name] = (value_data, value_type)
                        index += 1
                    except OSError as e:
                        if e.winerror == 259:  # No more data
                            break
                        else:
                            raise

                # Enumerate the subkeys under the key
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, index)
                        snapshot[root_key]['subkeys'].append(subkey_name)
                        index += 1
                    except OSError as e:
                        if e.winerror == 259:  # No more data
                            break
                        else:
                            raise

        except FileNotFoundError:
            pass  # The key doesn't exist

    return snapshot


def compare_registry_after_exe(exe_path):
    before_exe_snapshot = snapshot_registry()
    os.startfile(exe_path)
    after_exe_snapshot = snapshot_registry()
    return before_exe_snapshot == after_exe_snapshot




    