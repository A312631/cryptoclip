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
	rsa_encrypted_aes_key_base64 = base64.b64encode(rsa_encrypted_aes_key).decode("ascii")
	aes_encrypted_data_base64 = base64.b64encode(aes_encrypted_data).decode("ascii")

	body = textwrap.fill((rsa_encrypted_aes_key_base64 + ";" + aes_encrypted_data_base64), 64)

	return (HEADER + '\n' + body + '\n' + FOOTER)

def generate(keypair_name):
	print("generating " + str(combocrypt.RSA_KEYSIZE) + "-bit RSA keypair...")
	private_key = combocrypt.rsa_random_keypair()
	public_key = private_key.publickey()

	privkey_file = keypair_name + PRIVATE_KEY_EXTENSION
	pubkey_file = keypair_name + PUBLIC_KEY_EXTENSION

	print("writing keys to '" + privkey_file + "' and '" + pubkey_file + "'...")
	combocrypt.save_rsa_key(private_key, privkey_file)
	combocrypt.save_rsa_key(public_key, pubkey_file)

	print("done!")

def encrypt(pubkey_file):
	data = pyperclip.paste().encode("utf-8")

	if len(data) == 0:
		print("clipboard is empty!")
		return

	key_file_name = os.path.basename(pubkey_file)
	if "." not in key_file_name: # if the key file provided has no extension
		pubkey_file += PUBLIC_KEY_EXTENSION # assume public key extension

	public_key = combocrypt.load_rsa_key(pubkey_file) # TODO: catch exceptions

	rsa_encrypted_aes_key, aes_encrypted_data = combocrypt.combo_encrypt_data(data, public_key)
	result = format_output(rsa_encrypted_aes_key, aes_encrypted_data)

	pyperclip.copy(result)
	print("message successfully encrypted - the result has been copied to your clipboard")

def decrypt(privkey_file):
	clipboard = pyperclip.paste()

	if not (clipboard.startswith(HEADER) and clipboard.endswith(FOOTER)):
		print("clipboard does not contain a valid combocrypt message")
		return

	key_file_name = os.path.basename(privkey_file)
	if "." not in key_file_name: # if the key file provided has no extension
		privkey_file += PRIVATE_KEY_EXTENSION # assume private key extension

	body = clipboard[len(HEADER):-len(FOOTER)]

	rsa_encrypted_aes_key_base64, aes_encrypted_data_base64 = tuple(body.split(";"))
	rsa_encrypted_aes_key = base64.b64decode(rsa_encrypted_aes_key_base64)
	aes_encrypted_data = base64.b64decode(aes_encrypted_data_base64)

	private_key = combocrypt.load_rsa_key(privkey_file) # TODO: catch exceptions, move this before message processing
	decrypted = combocrypt.combo_decrypt_data(rsa_encrypted_aes_key, aes_encrypted_data, private_key).decode("utf-8")

	pyperclip.copy(decrypted)
	print("message successfully decrypted - the result has been copied to your clipboard")

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("mode", choices = ["generate", "encrypt", "decrypt"])
	parser.add_argument("key")

	args = parser.parse_args()

	{
	"generate": generate,
	"encrypt": encrypt,
	"decrypt": decrypt
	}[args.mode](args.key)

main()
