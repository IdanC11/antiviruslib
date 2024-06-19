# -*- coding: utf-8 -*-
"""
Created on Tue Apr 23 16:01:43 2024

@author: edanc
"""

import re
import sqlite3
import os
import socket
import hashlib


# A DICTIONARY FOR FILE TYPES -> {FILE TYPE: (SIGNATURE BYTES, SIGNATURE)}
FILES_SIGNATURES = {
    'png': (8, '89504E470D0A1A0A'),
    'zip': (4, '504B0304'),
    'exe': (2, '4D5A'),
    'jpg': (3, 'FFD8FF'),
    'jpeg': (3, 'FFD8FF'),
    'pdf': (7, '255044462D312E'),
    'mp4': (12, '000000186674797033677034')
}

# A DICTIONARY FOR FILE SIZES IN KB -> {FILE TYPE: (MIN SIZE, MAX SIZE)}
FILES_SIZES = {
    'png': (5, 11000),
    'jpg': (5, 11000),
    'jpeg': (5, 11000)
}

def get_file_signature(file_path, file_type):
    try:
        with open(file_path, 'rb') as file:
            sign_bytes = FILES_SIGNATURES[file_type][0]
            signature_bytes = file.read(sign_bytes)
            signature_hex = ''.join(format(byte, '02X') for byte in signature_bytes)
            return signature_hex
    except Exception as e:
        print(f"Error: {e}")
        return None

def is_signature_match(file_signature, file_type):
    signature = file_signature
    if signature != FILES_SIGNATURES[file_type][1]:
        return False
    return True

def is_size_match(sizeKB, file_type):
    if file_type in FILES_SIZES.keys():
        file_size = sizeKB
        min_size = FILES_SIZES[file_type][0]
        max_size = FILES_SIZES[file_type][1]

        if file_size > max_size or file_size < min_size:
            return False
    return True

class File:
    def __init__(self, path):
        self.file_path = path
        self.content = get_file_content(path)
        self.file_type = get_file_type(path)
        self.sha256 = calculate_hash2(self.file_path, hashlib.sha256)
        self.md5 = calculate_hash2(self.file_path, hashlib.md5)
        self.signature = get_file_signature(path, self.file_type)
        self.sizeKB = get_file_sizeKB(path)

def send_file(file_name, server_ip, server_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            with open(file_name, 'rb') as f:
                data = f.read()
                s.sendall(data)
            print(f"File {file_name} sent successfully.")
    except Exception as e:
        print(f"Failed to send file: {e}")
        
        
def receive_file(save_path, listen_ip, listen_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((listen_ip, listen_port))
            s.listen(1)
            print(f"Listening on {listen_ip}:{listen_port}...")

            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                with open(save_path, 'wb') as f:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        f.write(data)
                print(f"File received and saved to {save_path}.")
    except Exception as e:
        print(f"Failed to receive file: {e}")
        

def receive_exe_status(host='0.0.0.0', port=65432):
    """
    Starts the server to listen for incoming connections and print received strings.
    
    :param host: The hostname or IP address to bind the server to.
    :param port: The port number to bind the server to.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            if data:
                print(f"Received data: {data.decode()}")
        return data
    


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
    def get_hash_from_db(self, file, hash_algorithm_str, table_name="hashes"):
        path = file.file_path
        sql_str = "SELECT " + hash_algorithm_str + " FROM " + table_name + " WHERE file_path = ?"
        self.cursor.execute(sql_str, (path,))
        
        result = self.cursor.fetchone()
        self.connection.commit()
        if result:
            return result[0]
        else:
            self.add_hashes_to_db(path, file.sha256, file.md5)
        if hash_algorithm_str == "sha256":
            return file.sha256
        return file.md5
    
    # GETS sha256 AND md5 HASHES AND COMPARES THEM TO THE HASHES IN THE .db FILE
    # RETURNS BOOLEAN: TRUE -> THE HASHES ARE EQUAL | FALSE -> THE HASHES ARE NOT EQUAL
    def is_hashes_equal(self, file, current_hash, hash_algorithm_str):
        original_hash = self.get_hash_from_db(file, hash_algorithm_str)
        if current_hash != original_hash:
            return False
        return True
    
    # GETS A FILE PATH, 2 HASHES OF THE FILE (sha256, md5), A .db FILE PATH AND A TABLE NAME (optional)
    # ADDS THE FILE PATH AND THE HASHES TO THE DATA BASE, RETURNS None
    def add_hashes_to_db(self, file_path, sha256, md5, db_table="hashes"):
        self.cursor.execute("INSERT OR IGNORE INTO " + db_table + " (file_path, sha256, md5) VALUES (?, ?, ?)"
                          ,(file_path, sha256, md5))
        self.connection.commit()
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



# GETS A FILE PATH | RETURNS THE FILE'S CONTENT
def get_file_content(file_path):
    with open(file_path, 'rb') as f:
        content = b""
        while chunk := f.read(8192): # Read in 8KB chunks
            content += chunk
    return content 


def calculate_hash2(file_path, hash_algorithm=hashlib.sha256):
    # Open the file in binary mode and read its content
    with open(file_path, 'rb') as f:
        content = f.read()

    # Calculate the hash using the specified algorithm
    hash_func = hash_algorithm()
    hash_func.update(content)
    return hash_func.hexdigest()


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

 