# coin1 connects to pwnable.kr:9007 and attempts to find 100 counterfit coins 
# using a binary search.
from pwn import remote

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

# search performs a binary search
def search(numbers, conn):
    # We only have one answer to try. Keep inputting it until we get "Correct!"
    # TODO: Maybe handle "Wrong coin" at some point? We could surely never be
    # wrong...
    if len(numbers) == 1:
        conn.send(str(numbers[0]) + "\n")
        answer = conn.recvline()
        print(answer)
        if "Correct!" in answer:
            # Answer format is: 'Correct! (num_correct_coins)
            # We return the number in the parens.
            return answer[answer.find("(")+1:answer.find(")")]
        
        return search(numbers, conn)
    
    # Split our numbers into left and right sides of the binary tree.
    count = len(numbers)
    left = numbers[:count/2]
    right = numbers[count/2:]

    # Calculate expected weight.
    expected_weight = len(left)*10

    # Test the left weight.
    conn.send(" ".join(map(str, left)) + "\n")
    left_weight = conn.recvline()

    # If we happen to guess the right number
    if "Correct!" in left_weight:
        print(left_weight)
        return left_weight[left_weight.find("(")+1:left_weight.find(")")]
    
    # If left side has counterfit, we re-run search on just that side.
    if int(left_weight) != expected_weight:
        return search(left, conn)

    # If left side does not have counterfit, we know it has to be on the right
    # side, so we don't bother checking the weight.
    return search(right, conn)
    
def main():
    # Connect to server
    conn = remote("pwnable.kr", 9007)

    # Read explanation
    conn.recvuntil("- Ready? starting in 3 sec... -")
    conn.recvline()

    # Find 100 fake coins (starts at 0).
    while True:
        if find_fake(conn) == 99:
            break
    
    # Get our flag.
    print(conn.recvline())
    conn.interactive()

if __name__ == "__main__":
    main()
