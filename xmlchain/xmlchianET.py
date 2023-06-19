import hashlib
import xml.etree.ElementTree as ET
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def generate_keypair():
    return RSA.generate(2048)

def sign_data(private_key, data):
    h = SHA256.new(data.encode())
    return pkcs1_15.new(private_key).sign(h)

def verify_signature(public_key, signature, data):
    h = SHA256.new(data.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def hash_data(data, prev_hash):
    combined_data = data + prev_hash
    return hashlib.sha256(combined_data.encode()).hexdigest()

def create_block(data, prev_hash, signature, public_key):
    block = ET.Element("block")
    block.set("data", data)
    block.set("prev_hash", prev_hash)
    block.set("signature", signature.hex())
    # Replace newline characters with a placeholder
    public_key_str = public_key.export_key().decode().replace("\n", "{newline}")
    block.set("public_key", public_key_str)
    block.set("hash", hash_data(data, prev_hash))
    return block

def validate_chain(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    prev_hash = ""

    for block in root:
        data = block.get("data")
        signature = bytes.fromhex(block.get("signature"))
        # Revert the newline characters from the placeholder
        public_key_data = block.get("public_key").replace("{newline}", "\n")
        public_key = RSA.import_key(public_key_data)
        current_hash = block.get("hash")

        print(f"Checking block with data: '{data}'")

        if prev_hash != block.get("prev_hash"):
            return False

        if not verify_signature(public_key, signature, data):
            return False

        if current_hash != hash_data(data, prev_hash):
            return False

        prev_hash = current_hash

    return True

def prettify_xml(elem, level=0):
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            prettify_xml(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i
    return elem

def append_block(xml_file, block):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    root.append(block)
    prettify_xml(root)

    tree.write(xml_file, encoding='utf-8', xml_declaration=True)

def test_secure_document_sharing():
    # Step 1: Alice and Bob generate their respective key pairs
    alice_keypair = generate_keypair()
    bob_keypair = generate_keypair()

    # Step 2: Alice creates a new XML file called `secure_documents.xml` to store the blockchain
    root = ET.Element("blockchain")
    tree = ET.ElementTree(root)
    tree.write("secure_documents.xml")

    # Step 3: Alice adds her first document (e.g., a contract) to the blockchain and signs it
    alice_document = "Contract between Alice and Bob"
    alice_signature = sign_data(alice_keypair, alice_document)
    alice_block = create_block(alice_document, "", alice_signature, alice_keypair.publickey())
    append_block("secure_documents.xml", alice_block)

    # Step 4: Alice sends the XML file to Bob through a secure channel. Bob receives the file and verifies Alice's signature
    if validate_chain("secure_documents.xml"):
        print("The document has been successfully verified.")
    else:
        print("The document could not be verified.")

    # Step 5: Bob reads the contract, agrees to its terms, and adds a signed acknowledgment to the XML file
    bob_acknowledgment = "Bob agrees to the terms of the contract."
    bob_signature = sign_data(bob_keypair, bob_acknowledgment)
    prev_hash = alice_block.get("hash")
    bob_block = create_block(bob_acknowledgment, prev_hash, bob_signature, bob_keypair.publickey())
    append_block("secure_documents.xml", bob_block)

    # Step 6: Bob sends the updated XML file back to Alice. Alice verifies that Bob's signature is valid
    if validate_chain("secure_documents.xml"):
        print("Bob's acknowledgment has been successfully verified.")
    else:
        print("Bob's acknowledgment could not be verified.")


if __name__ == "__main__":
    test_secure_document_sharing()
