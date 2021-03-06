#include <cstdlib>
#include <cstdio>
#include <cerrno>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <error.h>
#include <vector>
#include <iostream>
#include <fstream>

#include "constants.h"

unsigned char query_oracle(unsigned char ctbuf[], size_t ctlen, int ifd[2], int ofd[2])
{
    int status;
    pid_t pid = fork();
    if (pid == 0)
    {
        // this is the child; it will simply exec into our desired
        // oracle program, but first it replaces stdin and stdout with
        // the above-created pipes so that the parent can both write to
        // and read from it
        dup2(ofd[0], STDIN_FILENO);
        dup2(ifd[1], STDOUT_FILENO);

        // ask kernel to deliver SIGTERM in case the parent dies
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        // run the oracle
        execl(ORACLE, ORACLE, (char *)NULL);
        // we'll never get here, unless execl fails for some reason
        exit(1);
    }
    else
    {
        ssize_t bytes_written = write(ofd[1], &ctlen, sizeof(ctlen));
        bytes_written = write(ofd[1], ctbuf, ctlen);
	// printf("Wrote %lu bytes\n", bytes_written);
        unsigned char result = 0;
        ssize_t bytes_read = read(ifd[0], &result, 1);
	// printf("Oracle responded: %c\n", result);
        waitpid(pid, &status, 0);
        return result;
    }
}

unsigned char find_padding (unsigned char ctbuf[], size_t ctlen, int ifd[2], int ofd[2])
{   
    char firstPaddingByte = ctbuf[ctlen - 1];

    unsigned char ctbuftmp[ctlen];
    for (int i = 0; i < ctlen ; i++) {
        ctbuftmp[i] = ctbuf[i];
    }

    char updatedPaddingByte = firstPaddingByte ^ 1;
    ctbuftmp[ctlen - 1] = updatedPaddingByte;
    unsigned char response1 = query_oracle(ctbuftmp, ctlen, ifd, ofd);
    ctbuftmp[ctlen - 1] = ctbuf[ctlen - 1];

    char secondPaddingByte = ctbuf[ctlen - 2];
    updatedPaddingByte = secondPaddingByte ^ 1;
    ctbuftmp[ctlen - 2] = updatedPaddingByte;
    unsigned char response2 = query_oracle(ctbuftmp, ctlen, ifd, ofd);
    ctbuftmp[ctlen - 2] = ctbuf[ctlen - 2];

    if(response1 == ERR_BADPAD && response2 == ERR_BADMAC) 
    {
        return 0x01;
    }

    for(unsigned char pad_byte = 1; pad_byte <= 16; pad_byte++)
    {
        char newPadByte = firstPaddingByte ^ pad_byte;
        ctbuftmp[ctlen - 1] = newPadByte;
        if(query_oracle(ctbuftmp, ctlen, ifd, ofd) == ERR_BADMAC)
        {
            ctbuftmp[ctlen - 1] = ctbuftmp[ctlen -1];
            return pad_byte ^ 0x01;
        }
    }
}

unsigned char decode_bytes(unsigned char padding, unsigned char ctbuf[], size_t ctlen, int ifd[2], int ofd[2])
{
    for(int i = 1; i <= padding; i++) {
        ctbuf[ctlen - i] ^= padding^(padding + 1);
    }

    ctbuf[ctlen - padding - 1] ^= (padding + 1);

    for(int i = 0; i < 128; i++) {
        ctbuf[ctlen - padding - 1] ^= (i ^ (i+1));
        unsigned char response = query_oracle(ctbuf, ctlen, ifd, ofd);
        if (response == ERR_BADMAC) {
            return i + 1;
        }
    }
}

int main(int argc, char * argv[])
{
        ssize_t bytes_read;

        // read the ciphertext from a file
        unsigned char ctbuf[IVLEN + MACLEN + CTLEN] = { '\0' };
        unsigned char ptbuf[IVLEN + MACLEN + CTLEN] = { '\0' };
        int ctfd =  open(CTFILE, O_RDONLY);
        if (ctfd == -1) error(1, errno, "opening %s", CTFILE);
        bytes_read = read(ctfd, ctbuf, IVLEN + MACLEN + CTLEN);
        if (bytes_read <= IVLEN + MACLEN) error(1, errno, "ciphertext too short");
        close(ctfd);

        // create some pipes for directional communication with the child process
        int ifd[2], ofd[2];
        if (pipe(ifd) != 0) error(1, errno, "creating input pipe");
        if (pipe(ofd) != 0) error(1, errno, "creating output pipe");

        // loop till we're done...
        size_t ctlen = bytes_read;
        size_t ptlen = 0;

        std::vector<unsigned char> plaintext;
        unsigned char padding;
        padding  = find_padding(ctbuf, ctlen, ifd, ofd);
        bool done = false;
        while(!done) {
            while(padding < 16) {
                unsigned char decrypted_value = decode_bytes(padding, ctbuf, ctlen, ifd, ofd);
                printf("This is the Decoded value returned:\n");
                printf("decimal Value: %d\n", decrypted_value);
                printf("ASCII character: %c\n", decrypted_value);
                plaintext.push_back(decrypted_value);
                padding = padding + 1;
            }
            padding = 0;
            ctlen = ctlen - 16;
            if (ctlen <= IVLEN + MACLEN) {
                done = true;
            }
        }

        int buffer = plaintext[0];
        if (buffer > plaintext.size() || plaintext[buffer - 1] != buffer)
        {
                buffer = 0; // no buffer case
        }
        int strLen = plaintext.size() - buffer;
        auto plaintextReverse = plaintext.rbegin();
        std::ofstream outputFile("plaintext.txt", std::ofstream::out);
        for (int i = 0; i < strLen; ++i)
        {
                outputFile << plaintextReverse[i];
        }

        outputFile.close();

        close(ofd[0]);
        close(ofd[1]);
        close(ifd[0]);
        close(ifd[1]);

        return 0;
}
