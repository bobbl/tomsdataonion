/* works only if unsigned int is 32 bits wide */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>



/* read from stdin */
unsigned input(unsigned char *dest)
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
int asciiz85(unsigned char *dest, unsigned char *src, unsigned int slen)
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
                pos++;
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
int bitfilter(unsigned char *dest, unsigned char *src, int slen)
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
int parity(unsigned char *dest, unsigned char *src, int slen)
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
int xorenc(unsigned char *dest, unsigned char *src, unsigned int slen)
{
    char *plain = "==[ Layer 4/6: =============\x0a\x0a ]";
        /*         11111111111111122222222222222222222211 
           char from first or second block */
    unsigned char key[32];
    unsigned i = 0;
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
        dest[i] = src[i] ^ key[(i << 27) >> 27]; /* i & 31 */
        i = i + 1;
    }
    return slen;
}


/* layer 4: UDP/IP */
int udpip(unsigned char *dest, unsigned char *src, unsigned int slen)
{
    unsigned int s = 0;
    unsigned int d = 0;
    while (s < slen) {
        if ((src[s] >> 4) != 4) return d;

        unsigned int total_length = (src[s+2] << 8) + src[s+3];
        unsigned int ip_header_len = (src[s] << 28) >> 26;

        // IP checksum
        unsigned int j;
        unsigned int ip_checksum = 0;
        for (j=0; j<ip_header_len; j=j+2) {
            ip_checksum = ip_checksum + 
                (((src[s+j] & 255) << 8) | (src[s+j+1] & 255));
        }
        ip_checksum = (ip_checksum & 0xFFFF) + ((ip_checksum >> 16) & 0xFFFF);
        if (ip_checksum > 0xFFFF) ip_checksum = (ip_checksum & 0xFFFF) + 1;

        unsigned udp_len = ((src[s+ip_header_len+4] & 255) << 8) |
            (src[s+ip_header_len+5] & 255);

        // UDP checksum
        unsigned udp_checksum;
        if ((src[s+ip_header_len+6]==0) && (src[s+ip_header_len+7]==0)) {
            udp_checksum = 0xFFFF; // no checksum -> always correct
        }
        else {
            // pseudo header
            udp_checksum = udp_len + 17;
            for (j=0; j<8; j=j+2) { // source and dest IP from IP header
                udp_checksum = udp_checksum +
                    (((src[s+12+j] & 255) << 8) | (src[s+12+j+1] & 255));
            }
            for (j=0; j<udp_len-1; j=j+2) { // UDP package
                udp_checksum = udp_checksum +
                    (((src[s+ip_header_len+j] & 255) << 8) |
                      (src[s+ip_header_len+j+1] & 255));
            }
            if (j != udp_len) { // odd UDP length => pad 0
                udp_checksum = udp_checksum +
                    ((src[s+ip_header_len+udp_len-1] & 255) << 8);
            }
            if (udp_checksum > 0xFFFF) 
                udp_checksum = (udp_checksum & 0xFFFF) +
                    ((udp_checksum >> 16) & 0xFFFF);
        }

        if ((src[s+9]==17) && // UDP protocol

            (src[s+12]==10) && // source ip
            (src[s+13]==1) &&
            (src[s+14]==1) &&
            (src[s+15]==10) &&

            (src[s+16]==10) && // dest ip
            (src[s+17]==1) &&
            (src[s+18]==1) &&
            ((src[s+19] & 255) == 200) &&

            ((src[s+ip_header_len+2] & 255) == 164) &&  // des port 42069
            (src[s+ip_header_len+3]==85) &&

            (ip_checksum==0xFFFF) &&
            (udp_checksum==0xFFFF))
        {
            for (j=8; j<udp_len; j++) {
                dest[d] = src[s+ip_header_len+j];
                d = d + 1;
            }
        }

        s = s + total_length;
    }
    return d;
}


unsigned xtime(unsigned x)
{
    unsigned int r = (x << 25) >> 24; /* (x << 1) & 255 */
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
        unsigned int r2 = (r << 25) >> 24; /* (r << 1) & 255 */
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


void aes_encrypt_block(uint8_t *ciphertext,
                         const uint8_t *key,
                         const uint8_t *plaintext)
{
    uint8_t buf[16];
    uint8_t enckey[32]; 
    uint8_t i, j, rcon;
    uint8_t a, b, c, d;

    i = 16;
    while (i--)
    {
	buf[i] = plaintext[i] ^ (enckey[i] = key[i]);
	enckey[16+i] = key[16 + i];
    }
    
    rcon = 1;
    for(j=1; j<14; j++)
    {
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

        for (i=0; i<16; i+=4)
	{
    	    a = buf[i]; 
    	    b = buf[i+1]; 
    	    c = buf[i+2];
    	    d = buf[i+3];
	    buf[i]   = b ^ c ^ d ^ xtime(a^b);
	    buf[i+1] = a ^ c ^ d ^ xtime(b^c);
    	    buf[i+2] = a ^ b ^ d ^ xtime(c^d);
    	    buf[i+3] = a ^ b ^ c ^ xtime(d^a);
	}

        if (j&1) 
        {
	    i = 16;
	    while (i--) buf[i] ^= enckey[i+16];
    	}
        else 
        {
	    buf[0] ^= (enckey[0] ^= sbox(enckey[29]) ^ rcon);
	    buf[1] ^= (enckey[1] ^= sbox(enckey[30]));
	    buf[2] ^= (enckey[2] ^= sbox(enckey[31]));
	    buf[3] ^= (enckey[3] ^= sbox(enckey[28]));
	    for(i=4; i<16; i++)
		buf[i] ^= (enckey[i] ^= enckey[i-4]);

	    enckey[16] ^= sbox(enckey[12]);
	    enckey[17] ^= sbox(enckey[13]);
	    enckey[18] ^= sbox(enckey[14]);
	    enckey[19] ^= sbox(enckey[15]);
	    for(i=20; i<32; i++) 
		enckey[i] ^= enckey[i-4];
	
	    rcon = (rcon<<1) ^ ((rcon&0x80) ? 0x1b : 0);
    	}
    }

    ciphertext[ 0] = (sbox(buf[ 0]) ^ (enckey[ 0] ^= sbox(enckey[29]) ^ rcon));
    ciphertext[ 1] = (sbox(buf[ 5]) ^ (enckey[ 1] ^= sbox(enckey[30])));
    ciphertext[ 2] = (sbox(buf[10]) ^ (enckey[ 2] ^= sbox(enckey[31])));
    ciphertext[ 3] = (sbox(buf[15]) ^ (enckey[ 3] ^= sbox(enckey[28])));
    ciphertext[ 4] = (sbox(buf[ 4]) ^ (enckey[ 4] ^= enckey[ 0]));
    ciphertext[ 5] = (sbox(buf[ 9]) ^ (enckey[ 5] ^= enckey[ 1]));
    ciphertext[ 6] = (sbox(buf[14]) ^ (enckey[ 6] ^= enckey[ 2]));
    ciphertext[ 7] = (sbox(buf[ 3]) ^ (enckey[ 7] ^= enckey[ 3]));
    ciphertext[ 8] = (sbox(buf[ 8]) ^ (enckey[ 8] ^= enckey[ 4]));
    ciphertext[ 9] = (sbox(buf[13]) ^ (enckey[ 9] ^= enckey[ 5]));
    ciphertext[10] = (sbox(buf[ 2]) ^ (enckey[10] ^= enckey[ 6]));
    ciphertext[11] = (sbox(buf[ 7]) ^ (enckey[11] ^= enckey[ 7]));
    ciphertext[12] = (sbox(buf[12]) ^ (enckey[12] ^= enckey[ 8]));
    ciphertext[13] = (sbox(buf[ 1]) ^ (enckey[13] ^= enckey[ 9]));
    ciphertext[14] = (sbox(buf[ 6]) ^ (enckey[14] ^= enckey[10]));
    ciphertext[15] = (sbox(buf[11]) ^ (enckey[15] ^= enckey[11]));
}


void aes_decrypt_block(uint8_t *plaintext,
                       const uint8_t *key,
                       const uint8_t *ciphertext)
{
    uint8_t buf[16];
    uint8_t deckey[32];

    uint8_t rcon;
    uint8_t i, j;
    uint8_t a, b, c, d, e, x, y, z;

    for (i = 0; i < 32; i++) deckey[i] = key[i];
    rcon = 1;
    for (j = 8;--j;) 
    {
        deckey[0] ^= sbox(deckey[29]) ^ rcon;
	deckey[1] ^= sbox(deckey[30]);
        deckey[2] ^= sbox(deckey[31]);
	deckey[3] ^= sbox(deckey[28]);
        for(i=4; i<16; i++) deckey[i] ^= deckey[i-4];

	deckey[16] ^= sbox(deckey[12]);
        deckey[17] ^= sbox(deckey[13]);
        deckey[18] ^= sbox(deckey[14]);
	deckey[19] ^= sbox(deckey[15]);
        for(i=20; i<32; i++) deckey[i] ^= deckey[i-4];
	
	rcon = (rcon<<1) ^ ((rcon&0x80) ? 0x1b : 0);
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
    for (j = 14; --j;)
    {
        if (j&1)           
        {
	    rcon = (rcon>>1) ^ ((rcon&1) ? 0x8d : 0);

	    for (i=15; i>=4; i--)
		buf[i] ^= (deckey[16+i] ^= deckey[16+i-4]);
	    buf[0] ^= (deckey[16] ^= sbox(deckey[12]));
	    buf[1] ^= (deckey[17] ^= sbox(deckey[13]));
	    buf[2] ^= (deckey[18] ^= sbox(deckey[14]));
	    buf[3] ^= (deckey[19] ^= sbox(deckey[15]));

	    for (i=15; i>=4; i--)
		deckey[i] ^= deckey[i-4];
	    deckey[0] ^= sbox(deckey[29]) ^ rcon;
	    deckey[1] ^= sbox(deckey[30]);
	    deckey[2] ^= sbox(deckey[31]);
	    deckey[3] ^= sbox(deckey[28]);
        }
        else
        {
	    i = 16;
	    while (i--) buf[i] ^= deckey[i];
	}

	for (i=0; i<16; i+=4)
        {
	    a = buf[i]; 
	    b = buf[i + 1]; 
	    c = buf[i + 2]; 
	    d = buf[i + 3];
            e = a ^ b ^ c ^ d;
    	    z = xtime(e);
	    x = e ^ xtime(xtime(z^a^c));
	    y = e ^ xtime(xtime(z^b^d));
            buf[i]   ^= x ^ xtime(a^b);
            buf[i+1] ^= y ^ xtime(b^c);
	    buf[i+2] ^= x ^ xtime(c^d);
	    buf[i+3] ^= y ^ xtime(d^a);
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
    }
    i = 16;
    while (i--) plaintext[i] = buf[i] ^ deckey[i];
}


uint64_t aes_unwrap_key(uint64_t *unwrapped_key,
                        const uint8_t *kek,
                        const uint64_t *wrapped_key,
                        unsigned n)
{
    unsigned i, jj;
    uint64_t A[2];
    uint64_t B[2];

    B[0] = wrapped_key[0];
    for (i=0; i<n; i++) unwrapped_key[i] = wrapped_key[i+1];

    for (jj=0; jj<6; jj++) {
        for (i=n; i!=0; i--) {
            A[0] = B[0];
            ((uint8_t *)A)[7] ^= n*(5-jj)+i; //n*j+i;
            A[1] = unwrapped_key[i-1];
            aes_decrypt_block((uint8_t *)B, kek, (uint8_t *)A);
            unwrapped_key[i-1] = B[1];
        }
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
int aes(unsigned char *dest, unsigned char *src, int slen)
{
    uint64_t key[4];
    uint64_t iv = aes_unwrap_key(key, (uint8_t *)src, (uint64_t *)(src+40), 4);
    if (iv != *(uint64_t *)(src+32)) return 0; /* IV not correct */

    int s = 96;
    uint8_t plaintext[16];
    while (s < slen) {
        aes_decode_ctr(dest+s-96,
                       (uint8_t *)key,
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
unsigned vm(unsigned char *dest, unsigned char *src, unsigned slen)
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
        unsigned opcode = src[regl[6]];
        regl[6]++;
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
                    unsigned value = reg[sreg];
                    if (sreg == 0) {
                        value = src[regl[6]]; // MVI
                        regl[6]++;
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
    unsigned len0, len1;

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
