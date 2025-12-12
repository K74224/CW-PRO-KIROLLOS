delimiter = "the message stop"

def main ():
    while True:
        print("**********Stegnography Project Kiro**********")
        print("1:Hide a Message in a Photo")
        print("2: Open the Secret Message")
        print("3: ESC")
        x = input("enter your choice")
        if x == "1":
            Encoding()
        elif x == "2":
            decode()
        elif x == "2":
            break
        else:
            print("Error Try Again")
#Encoding
def Encoding():
    print("----------Encoding Mode is ON----------")
    image_path = input("please enter path for the image:")
    output_path= input("please ennter the output path for the image:")
    print ("1: type Secret Message ")
    print("2: Load from File")
    choice = input("Enter Your Choice")
    if choice == "1":
        secret_message = input("Please Enter the Secret Message: ")
    elif choice == "2":
        File_Path = input ("Enter Text File Path")
        secret_message = read_text_file (File_Path)
    else:
        print ("Invalid Choice")
        return
    image_bytes = read_binary_file (image_path)
    delimiter_bytes = string_to_bytes (delimiter)
    payload_bytes = message_bytes + delimiter_bytes
    payload_bits = byte_to_bit (payload_bytes)
    message_bytes = string_to_bytes(image_bytes)
    data_offset = get_data_offset (image_bytes)
    available = len(image_bytes) - data_offset
    required = len(payload_bits)
    if required > available:
        print("no enough space")
    return
    # encode
    output = bytearray(image_bytes)
    index = 0
    for i in range (data_offset,len(output)):
        if index >= required:
            break
        else:
            output[i] = set_lsb(output[i],payload_bits[index])
            index += 1
    write_binary_file(output_path, encoded)
    print("Message Hidden")
#------------------------------------------------------------------------------#
def decode():
    print("----------decoding Mode is ON----------")
    encoded_message_path = input("please enter the path for the encoded image to retrieve the message")
    image_bytes = read_binary_file(encoded_message_path)
    data_offset = get_data_offset(image_bytes)
    delimiter_bytes = byte_to_bit(string_to_bytes(delimiter))
    delimiter_lengh = len(delimiter_bytes)
    delimiter_bts = byte_to_bit (delimiter_bytes)
    combinedbits = []
    for i in range(data_offset,len(image_bytes)):
        combinedbits.append(get_lsb(image_bytes[i]))
        if len (combinedbits) >= delimiter_lengh :
            if combinedbits[:-delimiter_lengh] == delimiter_bts:
                secret_msg_bits = combinedbits[:-delimiter_lengh]
                secret_msg_bytes = bit_to_byte(secret_msg_bits)
                Final = byte_to_string(secret_msg_bytes)
                print(f"Message Recovered Successfully the secret Message is: {Final}")
                return
    print("No Delimiter Found there is no secret Message here bye bye")
    
# ------------------------------------------------------------------------------#
def read_text_file(path):
    file = open(path,"r",encoding = "utf-8")    
    data = file.read()
    file.close()
    return data
#------------------------------------------------------------------------------#
def read_binary_file(path):
    file = open(path,"rb")
    data = file.read()
    file.close()
    return data
#------------------------------------------------------------------------------#
def write_binary_file(path,data):
    file = open(path,"wb")
    file.write(data)
    file.close()
#------------------------------------------------------------------------------#
def string_to_bytes(string):
    return list(string.encodeing("utf-8"))
#-----------------------------------------------------------------------------#
def byte_to_bit(byte):
    bits = []
    for i in byte:
        for j in range(7, -1, -1):
            bits.append((i >> j) & 1)
    return bits

#-------------------------------- bits to bytes ------------------------------#
def bit_to_byte(bit):
    if len(bit) % 8 != 0:
        raise ValueError("Bit list length must be a multiple of 8")

    output = []
    for i in range(0, len(bit), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (bit[i + j] & 1)
        output.append(byte)
    return output
#-----------------------------------------------------------------------------#
def byte_to_string(byte):
    return bytes(byte).decode("utf-8", errors="ignore")
#------------------------------------------------------------------------------#
def get_data_offset(b):
    return b[10] + (b[11] << 8) + (b[12] << 16) + (b[13] << 24)
#---------------------------------------------------------#
def set_lsb(byte,bit):
    return (byte & 0b11111110)
#
def get_lsb(byte):
    return(byte & 1)


main()
