# I need to comment this better.
from pwn import *

def find_fake(conn):
    # We get the following params from the server. Where
    # N is number of coins and C is chances.
    # N=353 C=9
    conn.recvuntil("N=")
    num_coins = conn.recvuntil(" ") # get number of coins
    conn.recvuntil("C=")
    chances = conn.recvuntil("\n") # get number of chances
    print("N={} C={}".format(num_coins, chances))

    return search(range(0, int(num_coins)), conn)

def search(numbers, conn):
    if len(numbers) == 1:
        conn.send(str(numbers[0]) + "\n")
        answer = conn.recvline()
        print(answer)
        if "Correct!" in answer:
            return answer[answer.find("(")+1:answer.find(")")]
        
        return search(numbers, conn)
    
    # We basically do a binary search here.
    count = len(numbers)
    left = numbers[:count/2]
    right = numbers[count/2:]
    expected_weight = (count/2)*10

    conn.send(" ".join(map(str, left)) + "\n")

    left_weight = conn.recvline()

    if "Correct!" in left_weight:
        return 1
    
    if int(left_weight) != expected_weight:
        return search(left, conn)

    return search(right, conn)
    
def main():
    # Connect to server
    conn = remote("pwnable.kr", 9007)

    # Read explanation
    conn.recvuntil("- Ready? starting in 3 sec... -")
    conn.recvline()

    while True:
        if find_fake(conn) == 99:
            break
    
    conn.recvline()
    conn.interactive()

if __name__ == "__main__":
    main()
