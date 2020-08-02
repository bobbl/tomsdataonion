/* works only if unsigned int is 32 bits wide */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>



/* read from stdin */
unsigned int input(unsigned char *dest)
{
    unsigned int d = 0;
    unsigned int ch = 0;
    while (ch < 256) {
        ch = getchar();
        dest[d] = ch;
        d = d + 1;
    }
    return d;
}


/* write to stdout */
void output(unsigned char *src, unsigned int len)
{
    unsigned int s = 0;
    while (s < len) {
        putchar(src[s]);
        s = s + 1;
    }
}


/* layer 0: decode Adobe flavoured ASCIIZ85 */
unsigned int asciiz85(unsigned char *dest, unsigned char *src, unsigned int slen)
{
    unsigned int s = 0;
    unsigned int d = 0;
    unsigned int ch = 0;
    unsigned int prev = 0;
    unsigned int loop = 1;
    unsigned int w = 0;
    unsigned int pos = 0;

    /* find begin marker */
    while (loop) {
        prev = ch;
        ch = src[s];
        s = s + 1;
        if (prev == '<') { // avoid &&
            if (ch == '~') {
                loop = 0;
            }
        }
    }

    while (s < slen) {
        ch = src[s];
        s = s + 1;
        if (ch=='>') {
            if (src[s - 2] == '~') {
                if (pos != 0) {

                    /* padding at the end */
                    unsigned int p = pos;
                    while (p < 5) {
                        w = (w * 85) + 84;
                        p = p + 1;
                    }
                    while (pos > 1) {
                        dest[d] = w >> 24;
                        d = d + 1;
                        w = w << 8;
                        pos = pos - 1;
                    }
                }
                return d;
            }
        }
        if (ch >= 33) {
            if (ch <= 117) {
                w = (w * 85) + (ch-33);
                pos = pos + 1;
                if (pos >= 5) {
                    dest[d    ] = w >> 24;
                    dest[d + 1] = w >> 16;
                    dest[d + 2] = w >> 8;
                    dest[d + 3] = w;
                    d = d + 4;
                    w = 0;
                    pos = 0;
                }
            }
        }
    }
    return 0;
}


/* layer 1: bitwise operations */
unsigned int bitfilter(unsigned char *dest, unsigned char *src, unsigned int slen)
{
    unsigned int s = 0;
    while (s < slen) {
        unsigned int v = src[s] ^ 85; /* 0x55 */
        dest[s] = (v >> 1) + (v << 7);
        s = s + 1;
    }
    return slen;
}


/* layer 2: parity bit */
unsigned int parity(unsigned char *dest, unsigned char *src, unsigned int slen)
{
    unsigned int bits = 0;
    unsigned int count = 0;
    unsigned int s = 0;
    unsigned int d = 0;

    while (s < slen) {
        unsigned int x = src[s];
        unsigned int parity = x ^ (x >> 1);
        parity = parity ^ (parity >> 2);
        parity = parity ^ (parity >> 4);
        if ((parity << 31) == 0) {
            bits = (bits << 7) + (x >> 1);
            count = count + 7;
        }
        if (count >= 8) {
            count = count - 8;
            dest[d] = bits >> count;
            d = d + 1;
        }
        s = s + 1;
    }
    return d;
}


/* layer 3: xor encryption */
unsigned int xorenc(unsigned char *dest, unsigned char *src, unsigned int slen)
{
    char *plain = "==[ Layer 4/6: =============\x0a\x0a ]";
        /*         11111111111111122222222222222222222211 
           char from first or second block */
    unsigned char key[32];
    unsigned int i = 0;
    while (i < 15) {
        key[i] = src[i] ^ plain[i];
        i = i + 1;
    }
    while (i < 30) {
        key[i] = src[i + 32] ^ plain[i];
        i = i + 1;
    }
    while (i < 32) {
        key[i] = src[i] ^ plain[i];
        i = i + 1;
    }

    i = 0;
    while (i < slen) {
        dest[i] = src[i] ^ key[(i << 27) >> 27];
        i = i + 1;
    }
    return slen;
}


unsigned int get_uint16be(unsigned char *p)
{
    return (p[0] << 8) + p[1];
}


/* layer 4: UDP/IP */
unsigned int udpip(unsigned char *dest, unsigned char *src, unsigned int slen)
{
    unsigned int s = 0;
    unsigned int d = 0;
    while (s < slen) {
        if ((src[s] >> 4) != 4) return d;

        unsigned int total_length = get_uint16be(src + s + 2);
        unsigned int ip_header_len = (src[s] << 28) >> 26;

        unsigned int ip_checksum = 0;
        unsigned int j = 0;
        while (j < ip_header_len) {
            ip_checksum = ip_checksum + get_uint16be(src + s + j);
            j = j + 2;
        }
        ip_checksum = ((ip_checksum << 16) >> 16) + (ip_checksum >> 16);
        ip_checksum = ((ip_checksum << 16) >> 16) + (ip_checksum >> 16);

        unsigned int udp_len      = get_uint16be(src + s + ip_header_len + 4);
        unsigned int udp_checksum = get_uint16be(src + s + ip_header_len + 6);
        if (udp_checksum == 0) {
            udp_checksum = 0xFFFF; // no checksum -> always correct
        }
        else {
            // pseudo header
            udp_checksum = udp_len + 17;
            j = 0;
            while (j < 8) { // source and dest IP from IP header
                udp_checksum = udp_checksum + get_uint16be(src + s + 12 + j);
                j = j + 2;
            }
            j = 0;
            while (j < udp_len - 1) { // UDP package
                udp_checksum = udp_checksum + 
                    get_uint16be(src + s + ip_header_len + j);
                j = j + 2;
            }
            if (j != udp_len) { // odd UDP length => pad 0
                udp_checksum = udp_checksum +
                    (src[s + ip_header_len + udp_len - 1] << 8);
            }
            udp_checksum = ((udp_checksum << 16) >> 16) + (udp_checksum >> 16);
            udp_checksum = ((udp_checksum << 16) >> 16) + (udp_checksum >> 16);
        }

        // avoid &&
        if (src[s+9] == 17) // UDP protocol
        if (src[s+12] == 10) // source ip
        if (src[s+13] == 1)
        if (src[s+14] == 1)
        if (src[s+15] == 10)
        if (src[s+16] == 10) // dest ip
        if (src[s+17] == 1)
        if (src[s+18] == 1)
        if (src[s+19] == 200)
        if (src[s + ip_header_len + 2] == 164) // dest port 42069
        if (src[s+ip_header_len+3] == 85)
        if (ip_checksum == 0xFFFF)
        if (udp_checksum == 0xFFFF)
        {
            j = 8;
            while (j < udp_len) {
                dest[d] = src[s + ip_header_len + j];
                d = d + 1;
                j = j + 1;
            }
        }
        s = s + total_length;
    }
    return d;
}


unsigned int xtime(unsigned int x)
{
    unsigned int r = (x << 25) >> 24;
    if (x > 127) r = 27 ^ r;
    return r;
}


/* Calculate multiplicative inverse in GF(2^8) 
  mulinv(x) = pow(255 - log(x)) */
unsigned  mulinv(unsigned x)
{
    unsigned int r = 1;
    unsigned int i = 0;
    while (i < 255) {
        if (r == x) {
            r = 1;
            x = 0; /* avoid that the condition a==x is true once again */
        }
        unsigned int r2 = (r << 25) >> 24;
        if (r > 127) r = r ^ r2 ^ 27;
        else r = r ^ r2;
        i = i + 1;
    }
    return r;
}


unsigned sbox(unsigned x)
{
    if (x == 0) return 99;
    unsigned int r = mulinv(x);
    r = r ^ ((r << 1) + (r >> 7)) ^
            ((r << 2) + (r >> 6)) ^
            ((r << 3) + (r >> 5)) ^
            ((r << 4) + (r >> 4)) ^ 99;
    return (r << 24) >> 24;
}


unsigned invsbox(unsigned x)
{
    if (x == 99) return 0;
    unsigned int r = ((x << 1) + (x >> 7)) ^
                     ((x << 3) + (x >> 5)) ^
                     ((x << 6) + (x >> 2)) ^ 5;
    return mulinv((r << 24) >> 24);
}



void iter_lower_key(unsigned char *key, unsigned int rcon)
{
    key[0] ^= sbox(key[29]) ^ rcon;
    key[1] ^= sbox(key[30]);
    key[2] ^= sbox(key[31]);
    key[3] ^= sbox(key[28]);
    unsigned int i = 4;
    while (i < 16) {
        key[i] = key[i] ^ key[i-4];
        i = i + 1;
    }
}

void iter_upper_key(unsigned char *key)
{
    key[16] = key[16] ^ sbox(key[12]);
    key[17] = key[17] ^ sbox(key[13]);
    key[18] = key[18] ^ sbox(key[14]);
    key[19] = key[19] ^ sbox(key[15]);
    unsigned int i = 20;
    while (i < 32) { 
        key[i] = key[i] ^ key[i-4];
        i = i + 1;
    }
}

void aes_encrypt_block(unsigned char *ciphertext,
                       unsigned char *key,
                       unsigned char *plaintext)
{
    unsigned char buf[16];
    unsigned char enckey[32]; 

    unsigned int i = 0;
    while (i < 16) {
        enckey[i]      = key[i];
        buf[i]         = plaintext[i] ^ enckey[i];
        enckey[i + 16] = key[i + 16];
        i = i + 1;
    }

    unsigned int rcon = 1;
    unsigned int upper = 0;
    unsigned int j = 1;
    while (j < 14) {
	buf[0] = sbox(buf[0]);
	buf[4] = sbox(buf[4]);
	buf[8] = sbox(buf[8]);
	buf[12] = sbox(buf[12]);
	i = sbox(buf[2]);	buf[2] = sbox(buf[10]);	buf[10] = i;
	i = sbox(buf[6]);	buf[6] = sbox(buf[14]);	buf[14] = i;
        i = sbox(buf[1]);	buf[1] = sbox(buf[5]);  
				buf[5] = sbox(buf[9]);
			        buf[9] = sbox(buf[13]);	buf[13] = i;
        i = sbox(buf[3]);	buf[3] = sbox(buf[15]);
			        buf[15] = sbox(buf[11]);
			        buf[11] = sbox(buf[7]);	buf[7] = i;

        i = 0;
        while (i < 16) {
            unsigned int a = buf[i]; 
            unsigned int b = buf[i+1]; 
            unsigned int c = buf[i+2];
            unsigned int d = buf[i+3];
            buf[i]   = b ^ c ^ d ^ xtime(a^b);
            buf[i+1] = a ^ c ^ d ^ xtime(b^c);
            buf[i+2] = a ^ b ^ d ^ xtime(c^d);
            buf[i+3] = a ^ b ^ c ^ xtime(d^a);
            i = i + 4;
        }

        if (upper) {
            upper = 0;
            iter_lower_key(enckey, rcon);
            iter_upper_key(enckey);
            rcon = xtime(rcon);
        } else upper = 16;

        i = 0;
        while (i < 16) {
            buf[i] = buf[i] ^ enckey[i + upper];
            i = i + 1;
        }
        j = j + 1;
    }

    iter_lower_key(enckey, rcon);
    ciphertext[ 0] = sbox(buf[ 0]) ^ enckey[ 0];
    ciphertext[ 1] = sbox(buf[ 5]) ^ enckey[ 1];
    ciphertext[ 2] = sbox(buf[10]) ^ enckey[ 2];
    ciphertext[ 3] = sbox(buf[15]) ^ enckey[ 3];
    ciphertext[ 4] = sbox(buf[ 4]) ^ enckey[ 4];
    ciphertext[ 5] = sbox(buf[ 9]) ^ enckey[ 5];
    ciphertext[ 6] = sbox(buf[14]) ^ enckey[ 6];
    ciphertext[ 7] = sbox(buf[ 3]) ^ enckey[ 7];
    ciphertext[ 8] = sbox(buf[ 8]) ^ enckey[ 8];
    ciphertext[ 9] = sbox(buf[13]) ^ enckey[ 9];
    ciphertext[10] = sbox(buf[ 2]) ^ enckey[10];
    ciphertext[11] = sbox(buf[ 7]) ^ enckey[11];
    ciphertext[12] = sbox(buf[12]) ^ enckey[12];
    ciphertext[13] = sbox(buf[ 1]) ^ enckey[13];
    ciphertext[14] = sbox(buf[ 6]) ^ enckey[14];
    ciphertext[15] = sbox(buf[11]) ^ enckey[15];
}


void aes_decrypt_block(unsigned char *plaintext,
                       unsigned char *key,
                       unsigned char *ciphertext)
{
    unsigned char buf[16];
    unsigned char deckey[32];

    unsigned int i = 0;
    while (i < 32) {
        deckey[i] = key[i];
        i = i + 1;
    }
    unsigned int rcon = 1;
    unsigned int j = 0;
    while (j < 7) {
        iter_lower_key(deckey, rcon);
        iter_upper_key(deckey);
        rcon = xtime(rcon);
        j = j + 1;
    }

    buf[ 0] = invsbox(ciphertext[ 0] ^ deckey[ 0]);
    buf[ 1] = invsbox(ciphertext[13] ^ deckey[13]);
    buf[ 2] = invsbox(ciphertext[10] ^ deckey[10]);
    buf[ 3] = invsbox(ciphertext[ 7] ^ deckey[ 7]);
    buf[ 4] = invsbox(ciphertext[ 4] ^ deckey[ 4]);
    buf[ 5] = invsbox(ciphertext[ 1] ^ deckey[ 1]);
    buf[ 6] = invsbox(ciphertext[14] ^ deckey[14]);
    buf[ 7] = invsbox(ciphertext[11] ^ deckey[11]);
    buf[ 8] = invsbox(ciphertext[ 8] ^ deckey[ 8]);
    buf[ 9] = invsbox(ciphertext[ 5] ^ deckey[ 5]);
    buf[10] = invsbox(ciphertext[ 2] ^ deckey[ 2]);
    buf[11] = invsbox(ciphertext[15] ^ deckey[15]);
    buf[12] = invsbox(ciphertext[12] ^ deckey[12]);
    buf[13] = invsbox(ciphertext[ 9] ^ deckey[ 9]);
    buf[14] = invsbox(ciphertext[ 6] ^ deckey[ 6]);
    buf[15] = invsbox(ciphertext[ 3] ^ deckey[ 3]);

    rcon = 0x80;
    unsigned int odd = 1;
    j = 0;
    while (j < 13) {
        if (odd) {
            odd = 0;
            if ((rcon << 31) == 0) rcon = rcon >> 1;
                              else rcon = (rcon >> 1) ^ 141;
            i = 16;
            while (i > 4) {
                i = i - 1;
                deckey[16+i] = deckey[16+i] ^ deckey[16+i-4];
            }
            deckey[16] = deckey[16] ^ sbox(deckey[12]);
            deckey[17] = deckey[17] ^ sbox(deckey[13]);
            deckey[18] = deckey[18] ^ sbox(deckey[14]);
            deckey[19] = deckey[19] ^ sbox(deckey[15]);

            i = 0;
            while (i < 16) {
                buf[i] = buf[i] ^ deckey[i + 16];
                i = i + 1;
            }

            i = 16;
            while (i > 4) {
                i = i - 1;
                deckey[i] = deckey[i] ^ deckey[i - 4];
            }
            deckey[0] ^= sbox(deckey[29]) ^ rcon;
            deckey[1] ^= sbox(deckey[30]);
            deckey[2] ^= sbox(deckey[31]);
            deckey[3] ^= sbox(deckey[28]);
        }
        else {
            odd = 1;
            i = 0;
            while (i < 16) {
                buf[i] = buf[i] ^ deckey[i];
                i = i + 1;
            }
        }

        i = 0;
        while (i < 16) {
            unsigned int a = buf[i]; 
            unsigned int b = buf[i+1]; 
            unsigned int c = buf[i+2];
            unsigned int d = buf[i+3];
            unsigned int z = xtime(a ^ b ^ c ^ d);
            unsigned int x = xtime(xtime(z^a^c));
            unsigned int y = xtime(xtime(z^b^d));
            buf[i]   = b ^ c ^ d ^ xtime(a^b) ^ x;
            buf[i+1] = a ^ c ^ d ^ xtime(b^c) ^ y;
            buf[i+2] = a ^ b ^ d ^ xtime(c^d) ^ x;
            buf[i+3] = a ^ b ^ c ^ xtime(d^a) ^ y;
            i = i + 4;
        }

	buf[0] = invsbox(buf[0]);
	buf[4] = invsbox(buf[4]);
	buf[8] = invsbox(buf[8]);
	buf[12] = invsbox(buf[12]);
	i = invsbox(buf[2]);	buf[2] = invsbox(buf[10]);	buf[10] = i;
	i = invsbox(buf[6]);	buf[6] = invsbox(buf[14]);	buf[14] = i;
        i = invsbox(buf[1]);	buf[1] = invsbox(buf[13]);  
				buf[13] = invsbox(buf[9]);
			    	buf[9] = invsbox(buf[5]);	buf[5] = i;
        i = invsbox(buf[3]);	buf[3] = invsbox(buf[7]);
			    	buf[7] = invsbox(buf[11]);
				buf[11] = invsbox(buf[15]);	buf[15] = i;

        j = j + 1;
    }
    i = 0;
    while (i < 16) {
        plaintext[i] = buf[i] ^ deckey[i];
        i = i + 1;
    }
}


uint64_t aes_unwrap_key(uint64_t *unwrapped_key,
                        unsigned char *kek,
                        const uint64_t *wrapped_key,
                        unsigned n)
{
    uint64_t A[2];
    uint64_t B[2];

    B[0] = wrapped_key[0];
    unsigned int i = 0;
    while (i < n) {
        unwrapped_key[i] = wrapped_key[i + 1];
        i = i + 1;
    }

    unsigned int jj = 0;
    while (jj < 6) {
        i = n;
        while (i != 0) {
            A[0] = B[0];
            ((unsigned char *)A)[7] ^= n*(5-jj)+i; //n*j+i;
            A[1] = unwrapped_key[i-1];
            aes_decrypt_block((unsigned char *)B, kek, (unsigned char *)A);
            unwrapped_key[i-1] = B[1];
            i = i - 1;
        }
        jj = jj + 1;
    }
    return B[0];
}


void aes_decode_ctr(unsigned char *plaintext,
                    unsigned char *key,
                    unsigned char *iv,
                    unsigned char *ciphertext)
{
    aes_encrypt_block(plaintext, key, iv);
    int i = 0;
    while (i<16) {
        plaintext[i] ^= ciphertext[i];
        i = i + 1;
    }

    // increment counter
    i = 15;
    iv[i] = iv[i] + 1;
    while (iv[i]==0) {
        if (i==0) return;
        i = i - 1;
        iv[i] = iv[i] + 1;
    }
}


/* layer 5: AES */
unsigned int aes(unsigned char *dest, unsigned char *src, int slen)
{
    uint64_t key[4];
    uint64_t iv = aes_unwrap_key(key, src, (uint64_t *)(src+40), 4);
    if (iv != *(uint64_t *)(src+32)) return 0; /* IV not correct */

    int s = 96;
    unsigned char plaintext[16];
    while (s < slen) {
        aes_decode_ctr(dest+s-96,
                       (unsigned char *)key,
                       src+80,
                       src+s);
        s = s + 16;
    }

    return slen - 96;
}


unsigned get_uint32le(unsigned char *p)
{
    return p[0] + (p[1] << 8) + (p[2] << 16) + (p[3] << 24);
}


/* layer 6: virtual machine */
unsigned vm(unsigned char *dest, unsigned char *src, unsigned int slen)
{
    unsigned char reg[8];
    unsigned int regl[8];
    unsigned int d = 0;
    while (d < 8) {
        reg[d] = 0;
        regl[d] = 0;
        d = d + 1;
    }
    d = 0;

    while (1) {
        unsigned int opcode = src[regl[6]];
        regl[6] = regl[6] + 1;
        unsigned int imm32 = get_uint32le(src + regl[6]);
        switch (opcode) {
            case 0x01: // HALT
                return d;
            case 0x02: // OUT
                dest[d] = reg[1];
                d = d + 1;
                break;
            case 0x21: // JEZ imm32
                if (reg[6] == 0) regl[6] = imm32;
                            else regl[6] = regl[6] + 4;
                break;
            case 0x22: // JNZ imm32
                if (reg[6] != 0) regl[6] = imm32;
                            else regl[6] = regl[6] + 4;
                break;
            case 0xC1:
                reg[6] = (reg[1] != reg[2]);
                break;
            case 0xC2: // ADD a <- b
                reg[1] = reg[1] + reg[2];
                break;
            case 0xC3: // SUB a <- b
                reg[1] = reg[1] - reg[2];
                break;
            case 0xC4: // XOR a <- b
                reg[1] = reg[1] ^ reg[2];
                break;
            case 0xE1: // APTR imm8
                regl[5] = regl[5] + src[regl[6]];
                regl[6] = regl[6] + 1;
                break;
            default: {
                unsigned int dreg = (opcode << 26) >> 29;
                unsigned int sreg = (opcode << 29) >> 29;

                if (opcode < 128) { // 8 bit
                    unsigned int value = reg[sreg];
                    if (sreg == 0) {
                        value = src[regl[6]]; // MVI
                        regl[6] = regl[6] + 1;
                    }
                    else if (sreg == 7) {
                        value = src[regl[5] + reg[3]];
                    }
                    if (dreg == 7) {
                        src[regl[5] + reg[3]] = value;
                    }
                    else {
                        reg[dreg] = value;
                    }
                }
                else { // 32 bit
                    if (sreg == 0) {
                        regl[6] = regl[6] + 4; // MVI32
                        regl[dreg] = imm32;
                    }
                    else {
                        regl[dreg] = regl[sreg];
                    }
                }
            }
        }
    }
}




int main()
{
    // double buffering with 384 KiByte per buffer
    unsigned char *buf0 = malloc(3 << 17);
    unsigned char *buf1 = malloc(3 << 17);
    unsigned int len0, len1;

    len0 = input(buf0);
    len1 = asciiz85(buf1, buf0, len0);

    len0 = asciiz85(buf0, buf1, len1);
    len1 = bitfilter(buf1, buf0, len0);

    len0 = asciiz85(buf0, buf1, len1);
    len1 = parity(buf1, buf0, len0);

    len0 = asciiz85(buf0, buf1, len1);
    len1 = xorenc(buf1, buf0, len0);

    len0 = asciiz85(buf0, buf1, len1);
    len1 = udpip(buf1, buf0, len0);

    len0 = asciiz85(buf0, buf1, len1);
    len1 = aes(buf1, buf0, len0);

    len0 = asciiz85(buf0, buf1, len1);
    len1 = vm(buf1, buf0, len0);

    output(buf1, len1);

    return 0;
}
