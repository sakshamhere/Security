# program for GCD

def gcd(a,b):
    
    return b if a==0 else gcd(b%a,a)

print(gcd(20,50))