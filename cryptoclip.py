import argparse
import textwrap
import base64
import os

import pyperclip

from combocrypt import combocrypt

PUBLIC_KEY_EXTENSION = ".pubkey"
PRIVATE_KEY_EXTENSION = ".privkey"

HEADER = "[BEGIN CRYPTOCLIP MESSAGE]"
FOOTER = "[END CRYPTOCLIP MESSAGE]"

def format_output(rsa_encrypted_aes_key, aes_encrypted_data):
	"""Format the output of combo_encrypt_data so that it may be easily copied and pasted for transit"""
	rsa_encrypted_aes_key_base64 = base64.b64encode(rsa_encrypted_aes_key).decode("ascii") # encode both parts of the message with base64
	aes_encrypted_data_base64 = base64.b64encode(aes_encrypted_data).decode("ascii")

	body = textwrap.fill((rsa_encrypted_aes_key_base64 + ";" + aes_encrypted_data_base64), 64) # separate the halves with a semicolon, wrap the body so that each line is 64 characters long at max

	return (HEADER + '\n' + body + '\n' + FOOTER) # combine the header, body, and footer

def generate(keypair_name):
	"""Generate a new RSA keypair, storing the keys in the given file destination"""
	print("generating " + str(combocrypt.RSA_KEYSIZE) + "-bit RSA keypair...")
	private_key = combocrypt.rsa_random_keypair() # generate a new RSA keypair
	public_key = private_key.publickey()

	privkey_file = keypair_name + PRIVATE_KEY_EXTENSION # add the extensions to the files
	pubkey_file = keypair_name + PUBLIC_KEY_EXTENSION

	print("writing keys to '" + privkey_file + "' and '" + pubkey_file + "'...")
	combocrypt.save_rsa_key(private_key, privkey_file) # write the keys to their files
	combocrypt.save_rsa_key(public_key, pubkey_file)

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

	public_key = combocrypt.load_rsa_key(pubkey_file) # TODO: catch exceptions

	rsa_encrypted_aes_key, aes_encrypted_data = combocrypt.combo_encrypt_data(clipboard.encode("utf-8"), public_key) # encode the clipboard contents and encrypt the data with the public key
	result = format_output(rsa_encrypted_aes_key, aes_encrypted_data) # format the output for transit

	pyperclip.copy(result) # copy the result to the clipboard
	print("message successfully encrypted - the result has been copied to your clipboard")

def decrypt(privkey_file):
	"""Decrypt the contents of the user's clipboard with ComboCrypt and the private key found in the given location"""
	clipboard = pyperclip.paste() # get the current clipboard

	if not (clipboard.startswith(HEADER) and clipboard.endswith(FOOTER)): # if the message doesn't start with the standard header and end with the standard footer
		print("clipboard does not contain a valid combocrypt message") # break
		return

	key_file_name = os.path.basename(privkey_file) # get the base name of the file provided by the user
	if "." not in key_file_name: # if the key file provided has no extension
		privkey_file += PRIVATE_KEY_EXTENSION # assume private key extension

	body = clipboard[len(HEADER):-len(FOOTER)] # remove the header and footer from the message

	rsa_encrypted_aes_key_base64, aes_encrypted_data_base64 = tuple(body.split(";")) # the message is split by a semicolon between two parts
	rsa_encrypted_aes_key = base64.b64decode(rsa_encrypted_aes_key_base64) # decode the parts
	aes_encrypted_data = base64.b64decode(aes_encrypted_data_base64)

	private_key = combocrypt.load_rsa_key(privkey_file) # TODO: catch exceptions, move this before message processing
	decrypted = combocrypt.combo_decrypt_data(rsa_encrypted_aes_key, aes_encrypted_data, private_key).decode("utf-8") # decrypt and decode the data

	pyperclip.copy(decrypted) # copy the result to the clipboard
	print("message successfully decrypted - the result has been copied to your clipboard")

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

main()
