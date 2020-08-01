#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>



/* read from stdin */
int input(char *dest)
{
    int d = 0;
    int ch = 0;
    while (ch >= 0) {
        ch = getchar();
        dest[d] = ch;
        d = d + 1;
    }
    return d;
}


/* write to stdout */
void output(char *src, int len)
{
    int s = 0;
    while (s < len) {
        putchar(src[s]);
        s = s + 1;
    }
}


/* layer 0: decode Adobe flavoured ASCIIZ85 */
int asciiz85(char *dest, char *src, int slen)
{
    /* find begin marker */
    int s = 0;
    int d = 0;
    int ch = 0;
    int prev = 0;
    while ((prev!='<') | (ch!='~')) {
        prev = ch;
        ch = src[s];
        s = s + 1;
    }

    unsigned long w = 0;
    unsigned pos = 0;
    while (s < slen) {
        ch = src[s++];
        if ((ch=='>') && (src[s-2]=='~')) break;
        if ((ch>=33) && (ch<=117)) {
            w = w*85 + (ch-33);
            pos++;
            if (pos >= 5) {
                dest[d++] = ((w >> 24) & 255);
                dest[d++] = ((w >> 16) & 255);
                dest[d++] = ((w >> 8) & 255);
                dest[d++] = (w & 255);
                w = 0;
                pos = 0;
            }
        }
    }

    /* padding at the end */
    if (pos != 0) {
        int p = pos;
        while (p < 5) {
            w = w*85 + 84;
            p++;
        }
        while (pos > 1) {
            dest[d++] = ((w >> 24) & 255);
            w = w << 8;
            pos--;
        }
    }
    return d;
}


/* layer 1: bitwise operations */
int bitfilter(char *dest, char *src, int slen)
{
    int s = 0;
    while (s < slen) {
        int v = src[s] ^ 85; /* 0x55 */
        dest[s] = ((v & 255) >> 1) | ((v & 1) << 7);
        s = s + 1;
    }
    return slen;
}


/* layer 2: parity bit */
int parity(char *dest, char *src, int slen)
{
    int bits = 0;
    int count = 0;
    int s = 0;
    int d = 0;
    while (s < slen) {
        int v = src[s];
        unsigned parity = __builtin_popcount(v & 254);
        if ((v & 1) == (parity & 1)) {
            bits = (bits << 7) | ((v >> 1) & 127);
            count = count + 7;
        }
        if (count >= 8) {
            dest[d] = ((bits >> (count-8)) & 255);
            d = d + 1;
            count = count - 8;
        }
        s = s + 1;
    }
    return d;
}


/* layer 3: xor encryption */
int xorenc(char *dest, char *src, int slen)
{
    char *plain = "==[ Layer 4/6: " "=============\x0a\x0a" " ]";
    char key[32];

    int i = 0;
    while (i<15) {
        key[i] = src[i] ^ plain[i];
        i = i + 1;
    }
    while (i<30) {
        key[i] = src[i+32] ^ plain[i];
        i = i + 1;
    }
    while (i<32) {
        key[i] = src[i] ^ plain[i];
        i = i + 1;
    }

    i = 0;
    while (i < slen) {
        dest[i] = src[i] ^ key[i & 31];
        i = i + 1;
    }
    return slen;
}


/* layer 4: UDP/IP */
int udpip(char *dest, char *src, int slen)
{
    int s = 0;
    int d = 0;
    while (s < slen) {
        if ((src[s] & 0xF0) != 0x40) break;

        int total_length = ((src[s+2] & 255) << 8) | (src[s+3] & 255);
        unsigned ip_header_len = (src[s] & 15) << 2;

        // IP checksum
        unsigned j;
        unsigned ip_checksum = 0;
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


#define XTIME(x)        ((((x)&0x80) ? 0x1b : 0) ^ ((x)<<1))
#define SBOX(x)         rijndael_sbox(x)
#define INVSBOX(x)      rijndael_invsbox(x)


/* Calculate multiplicative inverse in GF(2^8) 
  mulinv(x) = pow(255 - log(x)) */
uint8_t rijndael_mulinv(uint8_t x)
{
    unsigned i;
    uint8_t r=1;
    for (i=0; i<255; i++) {
        if (r==x) {
            r = 1;
            x = 0; /* avoid that the condition a==x is true once again */
        }
        r = r ^ (r<<1) ^ ((r&0x80) ? 0x1b : 0);
    }
    return r;
}


uint8_t rijndael_sbox(uint8_t x)
{
    uint8_t a;

    if (x==0) return 0x63;

    a = rijndael_mulinv(x);
    return (a ^ ((a<<1)|(a>>7)) ^ ((a<<2)|(a>>6)) ^
                ((a<<3)|(a>>5)) ^ ((a<<4)|(a>>4)) ^ 0x63);
}


uint8_t rijndael_invsbox(uint8_t x)
{
    if (x==0x63) return 0;
    return rijndael_mulinv( ((x<<1)|(x>>7)) ^ ((x<<3)|(x>>5)) ^ ((x<<6)|(x>>2))	^ 5);
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
	buf[0] = SBOX(buf[0]);
	buf[4] = SBOX(buf[4]);
	buf[8] = SBOX(buf[8]);
	buf[12] = SBOX(buf[12]);
	i = SBOX(buf[2]);	buf[2] = SBOX(buf[10]);	buf[10] = i;
	i = SBOX(buf[6]);	buf[6] = SBOX(buf[14]);	buf[14] = i;
        i = SBOX(buf[1]);	buf[1] = SBOX(buf[5]);  
				buf[5] = SBOX(buf[9]);
			        buf[9] = SBOX(buf[13]);	buf[13] = i;
        i = SBOX(buf[3]);	buf[3] = SBOX(buf[15]);
			        buf[15] = SBOX(buf[11]);
			        buf[11] = SBOX(buf[7]);	buf[7] = i;

        for (i=0; i<16; i+=4)
	{
    	    a = buf[i]; 
    	    b = buf[i+1]; 
    	    c = buf[i+2];
    	    d = buf[i+3];
	    buf[i]   = b ^ c ^ d ^ XTIME(a^b);
	    buf[i+1] = a ^ c ^ d ^ XTIME(b^c);
    	    buf[i+2] = a ^ b ^ d ^ XTIME(c^d);
    	    buf[i+3] = a ^ b ^ c ^ XTIME(d^a);
	}

        if (j&1) 
        {
	    i = 16;
	    while (i--) buf[i] ^= enckey[i+16];
    	}
        else 
        {
	    buf[0] ^= (enckey[0] ^= SBOX(enckey[29]) ^ rcon);
	    buf[1] ^= (enckey[1] ^= SBOX(enckey[30]));
	    buf[2] ^= (enckey[2] ^= SBOX(enckey[31]));
	    buf[3] ^= (enckey[3] ^= SBOX(enckey[28]));
	    for(i=4; i<16; i++)
		buf[i] ^= (enckey[i] ^= enckey[i-4]);

	    enckey[16] ^= SBOX(enckey[12]);
	    enckey[17] ^= SBOX(enckey[13]);
	    enckey[18] ^= SBOX(enckey[14]);
	    enckey[19] ^= SBOX(enckey[15]);
	    for(i=20; i<32; i++) 
		enckey[i] ^= enckey[i-4];
	
	    rcon = (rcon<<1) ^ ((rcon&0x80) ? 0x1b : 0);
    	}
    }

    ciphertext[ 0] = (SBOX(buf[ 0]) ^ (enckey[ 0] ^= SBOX(enckey[29]) ^ rcon));
    ciphertext[ 1] = (SBOX(buf[ 5]) ^ (enckey[ 1] ^= SBOX(enckey[30])));
    ciphertext[ 2] = (SBOX(buf[10]) ^ (enckey[ 2] ^= SBOX(enckey[31])));
    ciphertext[ 3] = (SBOX(buf[15]) ^ (enckey[ 3] ^= SBOX(enckey[28])));
    ciphertext[ 4] = (SBOX(buf[ 4]) ^ (enckey[ 4] ^= enckey[ 0]));
    ciphertext[ 5] = (SBOX(buf[ 9]) ^ (enckey[ 5] ^= enckey[ 1]));
    ciphertext[ 6] = (SBOX(buf[14]) ^ (enckey[ 6] ^= enckey[ 2]));
    ciphertext[ 7] = (SBOX(buf[ 3]) ^ (enckey[ 7] ^= enckey[ 3]));
    ciphertext[ 8] = (SBOX(buf[ 8]) ^ (enckey[ 8] ^= enckey[ 4]));
    ciphertext[ 9] = (SBOX(buf[13]) ^ (enckey[ 9] ^= enckey[ 5]));
    ciphertext[10] = (SBOX(buf[ 2]) ^ (enckey[10] ^= enckey[ 6]));
    ciphertext[11] = (SBOX(buf[ 7]) ^ (enckey[11] ^= enckey[ 7]));
    ciphertext[12] = (SBOX(buf[12]) ^ (enckey[12] ^= enckey[ 8]));
    ciphertext[13] = (SBOX(buf[ 1]) ^ (enckey[13] ^= enckey[ 9]));
    ciphertext[14] = (SBOX(buf[ 6]) ^ (enckey[14] ^= enckey[10]));
    ciphertext[15] = (SBOX(buf[11]) ^ (enckey[15] ^= enckey[11]));
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
        deckey[0] ^= SBOX(deckey[29]) ^ rcon;
	deckey[1] ^= SBOX(deckey[30]);
        deckey[2] ^= SBOX(deckey[31]);
	deckey[3] ^= SBOX(deckey[28]);
        for(i=4; i<16; i++) deckey[i] ^= deckey[i-4];

	deckey[16] ^= SBOX(deckey[12]);
        deckey[17] ^= SBOX(deckey[13]);
        deckey[18] ^= SBOX(deckey[14]);
	deckey[19] ^= SBOX(deckey[15]);
        for(i=20; i<32; i++) deckey[i] ^= deckey[i-4];
	
	rcon = (rcon<<1) ^ ((rcon&0x80) ? 0x1b : 0);
    }

    buf[ 0] = INVSBOX(ciphertext[ 0] ^ deckey[ 0]);
    buf[ 1] = INVSBOX(ciphertext[13] ^ deckey[13]);
    buf[ 2] = INVSBOX(ciphertext[10] ^ deckey[10]);
    buf[ 3] = INVSBOX(ciphertext[ 7] ^ deckey[ 7]);
    buf[ 4] = INVSBOX(ciphertext[ 4] ^ deckey[ 4]);
    buf[ 5] = INVSBOX(ciphertext[ 1] ^ deckey[ 1]);
    buf[ 6] = INVSBOX(ciphertext[14] ^ deckey[14]);
    buf[ 7] = INVSBOX(ciphertext[11] ^ deckey[11]);
    buf[ 8] = INVSBOX(ciphertext[ 8] ^ deckey[ 8]);
    buf[ 9] = INVSBOX(ciphertext[ 5] ^ deckey[ 5]);
    buf[10] = INVSBOX(ciphertext[ 2] ^ deckey[ 2]);
    buf[11] = INVSBOX(ciphertext[15] ^ deckey[15]);
    buf[12] = INVSBOX(ciphertext[12] ^ deckey[12]);
    buf[13] = INVSBOX(ciphertext[ 9] ^ deckey[ 9]);
    buf[14] = INVSBOX(ciphertext[ 6] ^ deckey[ 6]);
    buf[15] = INVSBOX(ciphertext[ 3] ^ deckey[ 3]);

    rcon = 0x80;
    for (j = 14; --j;)
    {
        if (j&1)           
        {
	    rcon = (rcon>>1) ^ ((rcon&1) ? 0x8d : 0);

	    for (i=15; i>=4; i--)
		buf[i] ^= (deckey[16+i] ^= deckey[16+i-4]);
	    buf[0] ^= (deckey[16] ^= SBOX(deckey[12]));
	    buf[1] ^= (deckey[17] ^= SBOX(deckey[13]));
	    buf[2] ^= (deckey[18] ^= SBOX(deckey[14]));
	    buf[3] ^= (deckey[19] ^= SBOX(deckey[15]));

	    for (i=15; i>=4; i--)
		deckey[i] ^= deckey[i-4];
	    deckey[0] ^= SBOX(deckey[29]) ^ rcon;
	    deckey[1] ^= SBOX(deckey[30]);
	    deckey[2] ^= SBOX(deckey[31]);
	    deckey[3] ^= SBOX(deckey[28]);
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
    	    z = XTIME(e);
	    x = e ^ XTIME(XTIME(z^a^c));
	    y = e ^ XTIME(XTIME(z^b^d));
            buf[i]   ^= x ^ XTIME(a^b);
            buf[i+1] ^= y ^ XTIME(b^c);
	    buf[i+2] ^= x ^ XTIME(c^d);
	    buf[i+3] ^= y ^ XTIME(d^a);
        }

	buf[0] = INVSBOX(buf[0]);
	buf[4] = INVSBOX(buf[4]);
	buf[8] = INVSBOX(buf[8]);
	buf[12] = INVSBOX(buf[12]);
	i = INVSBOX(buf[2]);	buf[2] = INVSBOX(buf[10]);	buf[10] = i;
	i = INVSBOX(buf[6]);	buf[6] = INVSBOX(buf[14]);	buf[14] = i;
        i = INVSBOX(buf[1]);	buf[1] = INVSBOX(buf[13]);  
				buf[13] = INVSBOX(buf[9]);
			    	buf[9] = INVSBOX(buf[5]);	buf[5] = i;
        i = INVSBOX(buf[3]);	buf[3] = INVSBOX(buf[7]);
			    	buf[7] = INVSBOX(buf[11]);
				buf[11] = INVSBOX(buf[15]);	buf[15] = i;
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


void aes_decode_ctr(uint8_t *plaintext,
                    const uint8_t *key,
                    uint8_t *iv,
                    const uint8_t *ciphertext)
{
    aes_encrypt_block((uint8_t *)plaintext, (uint8_t *)key, (uint8_t *)iv);
    int i=0;
    while (i<16) {
        plaintext[i] ^= ciphertext[i];
        i = i + 1;
    }

    // increment counter
    i = 15;
    iv[i] = iv[i] + 1;
    while (iv[i]==0 && i!=0) {
        i = i - 1;
        iv[i] = iv[i] + 1;
    }
}


/* layer 5: AES */
int aes(char *dest, char *src, int slen)
{
    uint64_t key[4];
    uint64_t iv = aes_unwrap_key(key, (uint8_t *)src, (uint64_t *)(src+40), 4);
    if (iv != *(uint64_t *)(src+32)) {
        printf("IV not correct\n");
        exit(1);
    }

    int s = 96;
    uint8_t plaintext[16];
    while (s < slen) {
        aes_decode_ctr((uint8_t *)dest+s-96,
                       (uint8_t *)key,
                       (uint8_t *)src+80,
                       (uint8_t *)src+s);
        s = s + 16;
    }

    return slen - 96;
}


/* layer 6: virtual machine */
int vm(char *dest, char *src, int slen)
{
    int d = 0;

    uint8_t reg[8];
    uint32_t regl[8];

#define PC regl[6]

#define GET_UINT32_LITTLEENDIAN(p)              \
    ((uint32_t)(((unsigned char *)(p))[0])        | \
    ((uint32_t)(((unsigned char *)(p))[1]) << 8)  | \
    ((uint32_t)(((unsigned char *)(p))[2]) << 16) | \
    ((uint32_t)(((unsigned char *)(p))[3]) << 24))


    int i;
    for (i=0; i<8; i++) {
        reg[i] = 0;
        regl[i] = 0;
    }

    while (1) {
        unsigned opcode = src[PC] & 255;
        PC++;
        switch (opcode) {
            case 0x01: // HALT
                return d;
            case 0x02: // OUT
                dest[d] = reg[1];
                d = d + 1;
                break;
            case 0x21: // JEZ imm32
                PC = (reg[6] == 0) ? GET_UINT32_LITTLEENDIAN(src+PC)
                                   : PC + 4;
                break;
            case 0x22: // JNZ imm32
                PC = (reg[6] != 0) ? GET_UINT32_LITTLEENDIAN(src+PC)
                                   : PC + 4;
                break;
            case 0xC1:
                reg[6] = (reg[1]==reg[2]) ? 0 : 1;
                break;
            case 0xC2: // ADD a <- b
                reg[1] += reg[2];
                break;
            case 0xC3: // SUB a <- b
                reg[1] -= reg[2];
                break;
            case 0xC4: // XOR a <- b
                reg[1] ^= reg[2];
                break;
            case 0xE1: // APTR imm8
                regl[5] += (src[PC] & 255);
                PC++;
                break;
            default: {
                unsigned dreg = (opcode >> 3) & 7;
                unsigned sreg = opcode & 7;

                if (opcode < 0x80) { // 8 bit
                    uint8_t value = reg[sreg];
                    if (sreg == 0) {
                        value = src[PC]; // MVI
                        PC++;
                    }
                    else if (sreg == 7) {
                        value = src[regl[5]+(reg[3] & 255)];
                    }
                    if (dreg == 7) {
                        src[regl[5]+(reg[3] & 255)] = value;
                    }
                    else {
                        reg[dreg] = value;
                    }
                }
                else { // 32 bit
                    uint32_t v32 = regl[sreg];
                    if (sreg == 0) {
                        v32 = GET_UINT32_LITTLEENDIAN(src+PC); // MVI32
                        PC += 4;
                    }
                    regl[dreg] = v32; 
                }
            }
        }
    }
}




int main()
{
    // double buffering with 384 KiByte per buffer
    char *buf0 = malloc(3 << 17);
    char *buf1 = malloc(3 << 17);
    int len0, len1;

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
