# XMLchain

XMLchain is a Python package for creating, verifying, and updating blockchainified XML files.

## Installation

You can install XMLchain directly from the source:

```shell
git clone https://github.com/mehranmo/XMLchain.git
cd XMLchain
pip install .
```


## Usage

Here's a simple example of how to use XMLchain:

```python
from XMLchain import xmlchain

# Generate a key pair
private_key, public_key = xmlchain.generate_key_pair()

# Create a new block
block = xmlchain.create_block("previous_block_hash", "data", private_key)
# The `block` variable now contains a blockchainified XML block

# Validate the XML file
valid = xmlchain.validate_chain("xml_filename")
# The `valid` variable is True if the XML file is valid, and False otherwise

```

## Running Tests
Run tests with the following command:

```shell
python -m unittest discover tests
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
MIT [https://choosealicense.com/licenses/mit/]