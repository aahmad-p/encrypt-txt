import base64
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome import Random
import sys

def encrypt(key, source, encode = True):
    # use SHA-256 over our key to get a proper-sized AES key
    key = SHA256.new(key).digest()

    # generate IV
    IV = Random.new().read(AES.block_size)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    # calculate needed padding
    padding = AES.block_size - len(source) % AES.block_size

    # Python 2.x: source += chr(padding) * padding
    source += bytes([padding]) * padding

    # store the IV at the beginning and encrypt
    data = IV + encryptor.encrypt(source)

    return base64.b64encode(data).decode("latin-1") if encode else data


def decrypt(key, source, decode = True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))

    # use SHA-256 over our key to get a proper-sized AES key
    key = SHA256.new(key).digest()

    # extract the IV from the beginning
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)

    # decrypt
    data = decryptor.decrypt(source[AES.block_size:])

    # pick the padding value from the end; Python 2.x: ord(data[-1])
    padding = data[-1]

    # Python 2.x: chr(padding) * padding
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding...")

    return data[:-padding]  # remove the padding


if __name__ == '__main__':
    '''
        Task enumeration:
        1 - create encrypted file
        2 - decrypt file
        
        Run as:
            python main.py <inFile> <task>
    '''

    # input file and output files
    direc = 'C:/Users/nyiri/Desktop/'

    inFile = direc + sys.argv[1]
    task = int( sys.argv[2] )

    # get key from user
    myPass = input('Enter encryption key:')

    with open(inFile) as myFile:
        myData = myFile.read()

    outFile = direc + 'encinfo-20180617.txt'


    if task == 1:
        print('Encrypting and writing to file ...')

        # Encrypt data and write to file
        encrypted = encrypt(myPass.encode(), myData.encode())
        with open(outFile, 'w') as myEncFile:
            myEncFile.write(encrypted)
    elif task == 2:
        print('Decrypting ...')

        try:
            decrypted = decrypt(myPass.encode(), myData).decode()
            print("dec:\n  {}".format(decrypted))
        except:
            print('Now you need another way to see this data')
    else:
        pass