from cryptography.fernet import Fernet

# Generate a new encryption key
key = Fernet.generate_key()

# Save it to a file
with open("secret.key", "wb") as key_file:
    key_file.write(key)

print("Encryption key generated and saved as 'secret.key'.")
print("this is my change")
print("one more change")