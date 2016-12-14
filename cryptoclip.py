import argparse
import textwrap
import base64
import os

from datetime import datetime

import pyperclip
import combocrypt

RSA_KEYSIZE = 4096

PUBLIC_KEY_EXTENSION = ".pubkey"
PRIVATE_KEY_EXTENSION = ".privkey"

HEADER = "[BEGIN CRYPTOCLIP MESSAGE]"
FOOTER = "[END CRYPTOCLIP MESSAGE]"

def format_output(combocrypt_data):
	"""Format the output of combo_encrypt_data so that it may be easily copied and pasted for transit"""
	parts_base64 = [base64.b64encode(part).decode("ascii") for part in combocrypt_data]
	parts_combined = ";".join(parts_base64)
	body = textwrap.fill(parts_combined, 64) # separate the halves with a semicolon, wrap the body so that each line is 64 characters long at max

	return (HEADER + '\n' + body + '\n' + FOOTER) # combine the header, body, and footer

def process_input(cryptoclip_block):
	body = cryptoclip_block[len(HEADER):-len(FOOTER)]
	parts_base64 = body.split(";")
	parts = [base64.b64decode(part) for part in parts_base64]
	return tuple(parts)

def generate(keypair_name):
	"""Generate a new RSA keypair, storing the keys in the given file destination"""
	print("generating " + str(RSA_KEYSIZE) + "-bit RSA keypair...")
	public_key, private_key = combocrypt.generate_rsa_keypair(key_size = RSA_KEYSIZE) # generate a new RSA keypair

	pubkey_file = keypair_name + PUBLIC_KEY_EXTENSION # add the extensions to the files
	privkey_file = keypair_name + PRIVATE_KEY_EXTENSION

	print("writing keys to '" + pubkey_file + "' and '" + privkey_file + "'...")
	combocrypt.save_rsa_public_key(public_key, pubkey_file) # write the keys to their files
	combocrypt.save_rsa_private_key(private_key, privkey_file)

	print("done!")
	print()
	print("warning: never share your private key file! anyone in possession of your private key can read messages meant for you!")

def encrypt(pubkey_file):
	"""Encrypt the contents of the user's clipboard with ComboCrypt and the public key found in the given location"""
	clipboard = pyperclip.paste() # get the current clipboard

	if len(clipboard) == 0: # if there is nothing to encrypt
		print("clipboard is empty!")
		return

	key_file_name = os.path.basename(pubkey_file) # get the base name of the file provided by the user
	if "." not in key_file_name: # if the key file provided has no extension
		pubkey_file += PUBLIC_KEY_EXTENSION # assume public key extension

	public_key = combocrypt.load_rsa_public_key(pubkey_file) # TODO: catch exceptions

	combocrypt_data = combocrypt.combo_encrypt_data(clipboard.encode("utf-8"), public_key) # encode the clipboard contents and encrypt the data with the public key
	result = format_output(combocrypt_data) # format the output for transit

	pyperclip.copy(result) # copy the result to the clipboard
	print("message successfully encrypted - the result has been copied to your clipboard")

def decrypt(privkey_file):
	"""Decrypt the contents of the user's clipboard with ComboCrypt and the private key found in the given location"""
	clipboard = pyperclip.paste() # get the current clipboard

	if not (clipboard.startswith(HEADER) and clipboard.endswith(FOOTER)): # if the message doesn't start with the standard header and end with the standard footer
		print("clipboard does not contain a valid cryptoclip message") # break
		return

	key_file_name = os.path.basename(privkey_file) # get the base name of the file provided by the user
	if "." not in key_file_name: # if the key file provided has no extension
		privkey_file += PRIVATE_KEY_EXTENSION # assume private key extension

	combocrypt_data = process_input(clipboard)

	private_key = combocrypt.load_rsa_private_key(privkey_file) # TODO: catch exceptions, move this before message processing
	message, timestamp = combocrypt.combo_decrypt_data(*combocrypt_data, private_key)

	pyperclip.copy(message.decode("utf-8")) # copy the result to the clipboard
	print("message successfully decrypted - the result has been copied to your clipboard")
	print()

	message_age = (datetime.utcnow() - datetime.fromtimestamp(timestamp)) # subtract the UTC timestamps to get the age of the message
	days_old = message_age.days
	hours_old, remainder = divmod(message_age.seconds, (60 * 60)) # divide seconds by the number of seconds in an hour
	minutes_old, seconds_old = divmod(remainder, 60) # divide the remainder by the number of seconds in a minute
	print("INFO: this message is timestamped {} days, {} hours, {} minutes, and {} seconds old".format(days_old, hours_old, minutes_old, seconds_old)) # TODO: formatting

def main():
	parser = argparse.ArgumentParser(add_help = False) # create a standard ArgumentParser
	parser.add_argument("mode", choices = ["generate", "encrypt", "decrypt"]) # three mode choices
	parser.add_argument("key") # required key argument

	args = parser.parse_args()

	{
	"generate": generate,
	"encrypt": encrypt,
	"decrypt": decrypt
	}[args.mode](args.key) # run the mode provided by the user, passing the 'key' argument to the function

if __name__ == "__main__":
	main()
