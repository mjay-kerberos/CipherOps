import subprocess
import os

def call_cyberchef(input_data, operation, output_file=None):
    """
    Calls CyberChef with the specified operation on the input data.

    Args:
    input_data (str): The data to be processed by CyberChef.
    operation (str): The operation to perform in CyberChef (e.g., "To Base64").
    output_file (str): The file to save the output, if provided.
    """
    # Save input data to a temporary file
    input_file = "cyberchef_input.txt"
    with open(input_file, 'w') as file:
        file.write(input_data)

    command = f"cyberchef --input {input_file} --operation \"{operation}\""

    if output_file:
        command += f" --output {output_file}"
    else:
        output_file = "cyberchef_output.txt"
        command += f" --output {output_file}"

    subprocess.run(command, shell=True)

    # Read the output data
    with open(output_file, 'r') as file:
        result = file.read()

    # Clean up temporary files
    os.remove(input_file)
    if output_file:
        os.remove(output_file)

    return result

def call_john(input_file, wordlist=None):
    """
    Calls John the Ripper to crack the password in the input file.

    Args:
    input_file (str): The file containing the password hash to be cracked.
    wordlist (str): The wordlist to use for the attack, if provided.

    Returns:
    str: The cracked password or result.
    """
    command = f"john {input_file}"

    if wordlist:
        command += f" --wordlist={wordlist}"

    subprocess.run(command, shell=True)

    # Extract the result from John the Ripper's output
    command = "john --show " + input_file
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    return result.stdout

def call_factordb(input_number):
    """
    Calls FactorDB to factorize a given number.

    Args:
    input_number (str): The number to factorize.

    Returns:
    str: The factors of the input number.
    """
    command = f"factordb {input_number}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    return result.stdout

# Example Usage
if __name__ == "__main__":
    # Example of calling CyberChef
    encrypted_data = call_cyberchef("Hello, World!", "To Base64")
    print("CyberChef Result:", encrypted_data)

    # Example of calling John the Ripper
    cracked_password = call_john("password_hash.txt", "/usr/share/wordlists/rockyou.txt")
    print("John the Ripper Result:", cracked_password)

    # Example of calling FactorDB
    factors = call_factordb("123456789")
    print("FactorDB Result:", factors)
