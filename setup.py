from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.rst"), encoding = "utf-8") as f:
	long_description = f.read()

setup(
	name = "cryptoclip",
	version = "1.1.0",
	description = "Command-line implementation of ComboCrypt for clipboard data",
	long_description = long_description,
	url = "https://github.com/samrankin1/cryptoclip",
	author = "Sam Rankin",
	author_email = "sam.rankin@me.com",
	license = "MIT",
	classifiers = [
		"Development Status :: 4 - Beta",
		"Intended Audience :: End Users/Desktop",
		"License :: OSI Approved :: MIT License",
		"Natural Language :: English",
		"Operating System :: OS Independent",
		"Topic :: Utilities",
		"Programming Language :: Python :: 3",
		"Programming Language :: Python :: 3.3",
		"Programming Language :: Python :: 3.4",
		"Programming Language :: Python :: 3.5",
	],
	keywords = "encryption public-key rsa aes clipboard",
	py_modules = ["cryptoclip"],
	install_requires = ["combocrypt>=2.0.0", "pyperclip"],
	entry_points = {
		"console_scripts": ["cryptoclip = cryptoclip:main"]
    }
)