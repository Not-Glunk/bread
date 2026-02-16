import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import csv
import pandas as pd

import sys
import getpass

PROMPT_COLOR = "\u001b[38;5;221m"
INPUT_COLOR = "\u001b[38;5;214m"
LOG_COLOR = "\u001b[38;5;245m"
DEFAULT_COLOR = "\u001b[0m"

def sha256sum(input_string):
    sha256Hash = hashlib.sha256(input_string.encode()).hexdigest()
    return sha256Hash

def base64Encode(input_bytes):
    base64Encoded = base64.b64encode(input_bytes).decode('utf-8')
    return base64Encoded

def base64Decode(input_string):
    input_string += '=' * (-len(input_string) % 4) # make sure string respects 4 bytes
    base64Decoded = base64.b64decode(input_string)
    return base64Decoded  # returns bytes

def aes256Encrypt(plaintext, key_string):
    try:
        salt = get_random_bytes(16)
        key = hashlib.scrypt(
            key_string.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=32
        )
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return salt + iv + ciphertext

    except (ValueError, KeyError) as e:
        # print(f"Encryption error: {e}")
        return None

def aes256Decrypt(ciphertext, key_string):
    try:
        salt = ciphertext[:16]
        iv = ciphertext[16:32]
        ciphertext = ciphertext[32:]

        key = hashlib.scrypt(
            key_string.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=32
        )
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')
        return plaintext

    except (ValueError, KeyError) as e:
        # print(f"Decryption error: {e}")
        return None


def search_keyword_in_column(csv_file, column1, column2, keyword):
    """returns pd.DataFrame containing rows with specified keyword contained in column"""
    df = pd.read_csv(csv_file, sep=',', engine='python')
    
    mask = (df[column1].str.contains(keyword, case=False, na=False) | df[column2].str.contains(keyword, case=False, na=False))
    return df[mask]

def read_index(csv_file, index_number):
    """returns list containing row with specified index"""
    df = pd.read_csv(csv_file, sep=',', header=None, names=['index', 'type', 'domain', 'seedOrData', 'notes', 'pepper', 'format'], engine='python')

    # pandas 3.0 fix, delete this line and uncomment the one below if you're on a past version, like the one that ships on termux
    df.loc[:, 'index'] = pd.to_numeric(df['index'], errors='coerce')
    # df['index'] = pd.to_numeric(df['index'], errors='coerce')
    index_data = df[df['index'] == index_number].iloc[0].values.tolist()
    return index_data

def add_row(csv_file, new_entry):
    """appends entry to .csv given values as list"""
    rows = []
    with open(csv_file, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        header = next(reader)
        rows = list(reader)
    
    next_index = int(rows[-1][0]) + 1 if rows else 1
    new_entry.insert(0, next_index)
    rows.append(new_entry)
    
    with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(rows)

def generate_data_password(row, passphrase):
    """generates either sha256sum or decrypts aes256 given list or pd.DataFrame"""
    data = ''
    # if given a list, convert into pd.DataFrame
    if isinstance (row, list):
        row = pd.DataFrame([row], columns=['index', 'type', 'domain', 'seedOrData', 'notes', 'pepper', 'format'])

    if (row.iloc[0]['type'] == 'P'): # if password, compute hash
        data = sha256sum(row.iloc[0]['seedOrData'] + passphrase)
        if (pd.notna(row.iloc[0]['format'])): # if format, truncate hash
            data = data[:int(row.iloc[0]['format'])]
        if (pd.notna(row.iloc[0]['pepper'])): # if pepper, concat to hash
            data = row.iloc[0]['pepper'] + data
    
    if (row.iloc[0]['type'] == 'D'): # if data, decrypt aes256
        data = aes256Decrypt(base64Decode(row.iloc[0]['seedOrData']), passphrase)

    return data

def add_entry(csv_file, entry):
    """adds entry, if type=Data encrypts it prompting for password"""
    if (entry[0] == 'D'):
        passphrase = getpass.getpass(prompt=f"{PROMPT_COLOR}Passphrase: {INPUT_COLOR}"); std_delete_line()
        entry[2] = base64Encode(aes256Encrypt(entry[2], passphrase))
    add_row(csv_file, entry)

def delete_entry(csv_file, index_number):
    """deletes entry with given index, updates all following entries' index accordingly
    returns False if entry with given index does not exist"""
    df = pd.read_csv(csv_file, dtype={'format': 'Int64'})
    if index_number not in df['index'].values:
        return False

    # delete entry, update following indexes
    df = df[df['index'] != index_number]
    df['index'] = range(1, len(df) + 1)

    df.to_csv(csv_file, index=False)
    return True


def std_delete_line(times=None):
    """clears n number of lines from console"""
    if times is not None:
        times -= 1
        for i in range (times):
            sys.stdout.write("\x1b[1F")
            sys.stdout.write("\x1b[2K")
    sys.stdout.write("\x1b[1F")
    sys.stdout.write("\x1b[2K")

def input_entry():
    """prompts for a new entry's values and then stores in list"""
    entry = ["", "", "", "", "", ""] # = [type, domain, seedOrData, notes, pepper, format]
    entry[3] = ""
    entry[4] = ""
    entry[5] = ""

    entry[0] = input(f"{PROMPT_COLOR}type ('P' for Password, 'D' for Data): {INPUT_COLOR}").upper(); std_delete_line()
    while (entry[0] not in ['P', 'D']):
        print(f"{LOG_COLOR}`type` has to be either 'P' or 'D'")
        entry[0] = input(f"{PROMPT_COLOR}type ('P' for Password, 'D' for Data): {INPUT_COLOR}").upper(); std_delete_line(2)

    entry[1] = input(f"{PROMPT_COLOR}domain: {INPUT_COLOR}"); std_delete_line()
    while (entry[1] == "" or ',' in entry[1]):
        if (',' in entry[1]):
            print(f"{LOG_COLOR}`domain` cannot contain `,`")
        else:
            print(f"{LOG_COLOR}`domain` cannot be null")
        entry[1] = input(f"{PROMPT_COLOR}domain: {INPUT_COLOR}"); std_delete_line(2)

    entry[2] = input(f"{PROMPT_COLOR}seedOrData: {INPUT_COLOR}"); std_delete_line()
    while (entry[2] == "" or ',' in entry[2]):
        if (',' in entry[2]):
            print(f"{LOG_COLOR}`seedOrData` cannot contain `,`")
        else:
            print(f"{LOG_COLOR}`seedOrData` cannot be null")
        entry[2] = input(f"{PROMPT_COLOR}domain: {INPUT_COLOR}"); std_delete_line(2)
    
    entry[3] = input(f"{PROMPT_COLOR}notes: {INPUT_COLOR}"); std_delete_line()
    while (',' in entry[3]):
        print(f"{LOG_COLOR}`notes` cannot contain `,`")
        entry[3] = input(f"{PROMPT_COLOR}notes: {INPUT_COLOR}"); std_delete_line(2)

    if (entry[0] == 'P'):
        entry[4] = input(f"{PROMPT_COLOR}pepper: {INPUT_COLOR}"); std_delete_line()
        while (',' in entry[4]):
            print(f"{LOG_COLOR}`pepper cannot contain `,`")
            entry[4] = input(f"{PROMPT_COLOR}pepper: {INPUT_COLOR}"); std_delete_line(2)

        entry[5] = input(f"{PROMPT_COLOR}format (doesnt account for pepper): {INPUT_COLOR}"); std_delete_line()
        while (entry[5] != "" and not entry[5].isdigit()):
            print(f"{LOG_COLOR}`format` has to be an int")
            entry[5] = input(f"{PROMPT_COLOR}format (doesnt account for pepper): {INPUT_COLOR}"); std_delete_line(2)
    return entry

def print_entry(entry):
    """prints entries of a pd.DataFrame with proper padding
    prints type=Data value as a default string"""
    header = ["index", "type", "domain", "seed/data", "notes", "pepper", "format"]
    for index, row in entry.iterrows():
        if row["type"] == 'D':
            entry.at[index, "seedOrData"] = "bunch'o'chars"
    # calculate proper column width
    all_rows = [header] + entry.to_numpy().tolist()
    col_widths = [max(len(str(row[i])) for row in all_rows) for i in range(len(header))]

    print("  ".join(f"\u001b[38;5;54m{header[i]:<{col_widths[i]}}{DEFAULT_COLOR}" for i in range(len(header))))
    for _, row in entry.iterrows():
        row = row.copy()
        row["index"] = int(row["index"])
        row_list = row.to_list()
        print("  ".join(f"\u001b[38;5;69m{str(row_list[i]):<{col_widths[i]}}{DEFAULT_COLOR}" for i in range(len(row_list))))

def print_csv(csv_file):
    """prints entire csv file"""
    df = pd.read_csv(csv_file, sep=',', engine='python')
    print_entry(df)



print(
"\n"
"\u001b[38;5;178m     _                    _ \n"
"\u001b[38;5;178m    | |__ _ _ ___ __ _ __| |  \u001b[38;5;94m■■■\n"
"\u001b[38;5;178m    | '_ \\ '_/ -_) _` / _` |  \u001b[38;5;222m■■■\u001b[38;5;94m■\n"
"\u001b[38;5;178m    |_.__/_| \\___\\__,_\\__,_|  \u001b[38;5;222m■■■\u001b[38;5;94m■\n"
"\n"
"\u001b[38;5;178m  ~ crackhead password manager™ ~\n"
"\u001b[0m")

menu_text = """
1) Attempt generating password/data
2) Search for entry
3) Add entry
4) Delete entry

0) Exit
"""
answer = "" # why the FUCK does python not have switch statements
while answer not in ['0', 'exit']:
    print(menu_text)
    
    answer = input(f"{PROMPT_COLOR}Select option: {INPUT_COLOR}")
    if (answer in ['1', 'generate']):
        std_delete_line(10)
        search_term = input(f"{PROMPT_COLOR}Search for: {INPUT_COLOR}"); std_delete_line()
        search_result = search_keyword_in_column('dough.csv', 'domain', 'notes', search_term)

        if search_result.empty:
            print(f"{LOG_COLOR}No results for '{INPUT_COLOR}"+search_term+f"{LOG_COLOR}'.")
        else:
            print(f"{LOG_COLOR}Results for '{INPUT_COLOR}"+search_term+f"{LOG_COLOR}':")
            print_entry(search_result)
            index_to_generate = int(input(f"{PROMPT_COLOR}Index to generate for: {INPUT_COLOR}")); std_delete_line()
            while index_to_generate != "" and not str(index_to_generate).isdigit():
                print(f"{LOG_COLOR}`index` has to be an int")
                index_to_generate = int(input(f"{PROMPT_COLOR}Index to generate for: {INPUT_COLOR}")); std_delete_line(2)
            input_passphrase = getpass.getpass(prompt=f"{PROMPT_COLOR}Passphrase: {INPUT_COLOR}").replace(f"{INPUT_COLOR}", ""); std_delete_line()

            generated_data = generate_data_password(read_index('dough.csv', index_to_generate), input_passphrase)
            if (generated_data is not None):
                print(f"{LOG_COLOR}Generated: {INPUT_COLOR}" + generated_data)
                input(f"{LOG_COLOR}Press Enter to continue"); std_delete_line(2); print(f"{LOG_COLOR}Generated: {INPUT_COLOR}eh! volevi!")
            else:
                print(f"{LOG_COLOR}Failed to generate data.")
        print(f"{LOG_COLOR}---{DEFAULT_COLOR}")

    elif (answer in ['2', 'search']):
        std_delete_line(10)
        search_term = input(f"{PROMPT_COLOR}Search for: {INPUT_COLOR}"); std_delete_line()
        search_result = search_keyword_in_column('dough.csv', 'domain', 'notes', search_term)
        if search_result.empty:
            print(f"{LOG_COLOR}No results for '{INPUT_COLOR}"+search_term+f"{LOG_COLOR}'.")
        else:
            print(f"{LOG_COLOR}Results for '{INPUT_COLOR}"+search_term+f"{LOG_COLOR}':")
            print_entry(search_result)
        print(f"{LOG_COLOR}---{DEFAULT_COLOR}")

    elif (answer in ['3', 'add']):
        std_delete_line(10)
        print(f"{DEFAULT_COLOR}"); std_delete_line()
        inputted_entry = input_entry()
        add_entry('dough.csv', inputted_entry)
        print(f"{LOG_COLOR}Successfully added entry '{INPUT_COLOR}"+inputted_entry[2]+f"{LOG_COLOR}'.")
        print(f"{LOG_COLOR}---{DEFAULT_COLOR}")

    elif (answer in ['4', 'delete']):
        std_delete_line(10)
        search_term = input(f"{PROMPT_COLOR}Search for: {INPUT_COLOR}"); std_delete_line()
        search_result = search_keyword_in_column('dough.csv', 'domain', 'notes', search_term)

        if search_result.empty:
            print(f"{LOG_COLOR}No results for '{INPUT_COLOR}"+search_term+f"{LOG_COLOR}'.")
        else:
            print(f"{LOG_COLOR}Results for '{INPUT_COLOR}"+search_term+f"{LOG_COLOR}':")
            print_entry(search_result)
            index_to_delete = int(input(f"{PROMPT_COLOR}Index to delete: {INPUT_COLOR}")); std_delete_line()
            while index_to_delete != "" and not str(index_to_delete).isdigit():
                print(f"{LOG_COLOR}`index` has to be an int")
                index_to_delete = int(input(f"{PROMPT_COLOR}Index to delete: {INPUT_COLOR}")); std_delete_line(2)

            answer_sure = input(f"{PROMPT_COLOR}are u suuuure? (type \"y eee s\" to confirm): {INPUT_COLOR}"); std_delete_line()
            if answer_sure not in ["y eee s"]:
                print(f"{LOG_COLOR}Aborted deletion.")
            else:
                if delete_entry('dough.csv', index_to_delete):
                    print(f"{LOG_COLOR}Successfully deleted entry with index {INPUT_COLOR}"+str(index_to_delete)+f"{LOG_COLOR}.")
                else:
                    print(f"{LOG_COLOR}No entry for index {INPUT_COLOR}"+str(index_to_delete)+f"{LOG_COLOR}.")
        print(f"{LOG_COLOR}---{DEFAULT_COLOR}")

    elif (answer in ['5', 'print']):
        std_delete_line(10)
        print(f"{LOG_COLOR}Displaying entire database:")
        print_csv('dough.csv')
        print(f"{LOG_COLOR}---{DEFAULT_COLOR}")

    elif (answer not in ['0', 'exit', '1', 'generate', '2', 'search', '3', 'add', '4', 'delete', '5', 'print']):
        std_delete_line(10)

    print(f"{DEFAULT_COLOR}"); std_delete_line()
std_delete_line(10)
print(f"{INPUT_COLOR}bye!")
