from authenticator import get_totp_token, generate_random_secret

SECRET_KEY = 'IFH2 NSQ5 L3BY IZCN C3BL OGKA SPER SKY7'

def main():
    # Testing with existing secret key.
    print(SECRET_KEY, get_totp_token(SECRET_KEY), sep=': ')

    # Testing with random generated secret keys.
    for _ in range(10):
        secret = generate_random_secret()
        print(secret, get_totp_token(secret), sep=': ')
    
if __name__ == '__main__':
    main()
