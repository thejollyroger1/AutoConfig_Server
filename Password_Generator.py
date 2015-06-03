import os, random, string

def password_create():
    global password
    length = 15
    chars = string.ascii_letters + string.digits + '!@#$%^&*()'
    random.seed = (os.urandom(1024))

    password = ''.join(random.choice(chars) for i in range(length))
    print "The password generated is : " + str(password)
if __name__ == "__main__":
    password_create()
