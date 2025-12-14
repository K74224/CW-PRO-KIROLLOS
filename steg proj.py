delimiter = "the message stop"

def main ():
    while True:
        print("***Stegnography Project Kiro***")
        print("1: Hide a Message in a Photo...")
        print("2: Open the Secret Message...")
        print("3: ESC")
        print("enter your choice")
        x = input()
        if x == "1":
            Encoding()
        elif x == "2":
            Decoding()
        elif x == "3":
            break
        else:
            print("Error Try Again")
#Encoding
def Encoding():
    print("----------Encoding Mode is ON----------")
    print("please enter path for the image:")
    image_path = input()
    print("please enter the output path for the image:")
    output_path= input()
    if not output_path.lower().endswith(".bmp"):
        output_path += "secret.bmp"

    print("1: type Secret Message ")
    print("2: Load from txt")
    choice = input("Enter Your Choice")
    if choice == "1":
        secret_message = input("Please Enter the Secret Message: ")
    elif choice == "2":
        File_Path = input ("Enter Text File Path")
        secret_message = read_text_file (File_Path)
    else:
        print ("Invalid Choice")
        return
    message_bytes = string_to_bytes(secret_message)
    delimiter_bytes = string_to_bytes (delimiter)
    payload_bytes = message_bytes + delimiter_bytes
    payload_bits = byte_to_bit(payload_bytes)
    image_bytes = read_binary_file (image_path)
    data_offset = image_bytes[10] + (image_bytes[11] << 8) + (image_bytes[12] << 16) + (image_bytes[13] << 24) # Data Offset
    available = len(image_bytes) - data_offset
    required = len(payload_bits)
    if required > available:
        print("No enough space,pick another image or change the message length...")
        return
    output = bytearray(image_bytes)
    x = 0
    for i in range(data_offset,len(output)):
        if x >= required:
            break
        else:
            output[i] = (output[i] & 0b11111110) | ( payload_bits[x] & 1) # SET LSB
            x +=1
    write_binary_file(output_path,output)
    print(f"Secret Message Hidden in:{output_path}")
#------------------------------------------------------------------------------#
def Decoding():
    print("----------decoding Mode is ON----------")
    print("please enter the path for the encoded image to retrieve the message")
    encoded_message_path = input()
    image_bytes = read_binary_file(encoded_message_path)
    data_offset = image_bytes[10] + (image_bytes[11] << 8) + (image_bytes[12] << 16) + (image_bytes[13] << 24) # Data Offset
    delimiter_bytes = string_to_bytes(delimiter)
    delimiter_bits = byte_to_bit (delimiter_bytes)
    delimiter_length = len(delimiter_bits)
    extracted_bits = []
    for i in range(data_offset,len(image_bytes)):
        extracted_bits.append(image_bytes[i] & 1) #Get LSB
        if len(extracted_bits) >= delimiter_length:
            if extracted_bits[-delimiter_length:] == delimiter_bits:
                secret_msg_bits = extracted_bits[:-delimiter_length]
                Final = byte_to_string(bit_to_byte(secret_msg_bits)) 
                print(f"Message Recovered Successfully the secret Message is: {Final}")
                return
    print("No Delimiter Found there is no secret Message here bye bye")
    
# ------------------------------------------------------------------------------#
def read_text_file(path): #Read Text file
    file = open(path,"r",encoding = "utf-8")    
    data = file.read()
    file.close()
    return data
#------------------------------------------------------------------------------#
def read_binary_file(path): #Read Image bytes
    file = open(path,"rb")
    bytes = file.read()
    file.close()
    return bytes
#------------------------------------------------------------------------------#
def write_binary_file(path,bytes):#Save the new photo with hidden message
    file = open(path,"wb")
    file.write(bytes)
    file.close()
#------------------------------------------------------------------------------#
def string_to_bytes(string):
    return list(string.encode("utf-8"))
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


main()