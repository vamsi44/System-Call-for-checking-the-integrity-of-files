struct mode1args
{
	unsigned char flag; // flags to set the mode (1, 2, 3, etc. per mode)
	const char *filename; // the name of the file to verify integrity
	unsigned char *ibuf; // the integrity value (e.g., MD5 value) buffer
	unsigned int ilen; // length of ibuf
};

struct mode2args
{
	/* data */
	unsigned char flag; // flags to set the mode (1, 2, 3, etc. per mode)
	const char *filename; // the name of the file to compute integrity
	unsigned char *ibuf; // the integrity value (e.g., MD5 value) buffer
	unsigned int ilen; // length of ibuf
	const char *credbuf; // credentials buffer
	unsigned int clen; // length of credbuf
};

struct mode3args
{
	unsigned char flag; // flags to set the mode (1, 2, 3, etc. per mode)
	const char *filename; // the name of the file to open+verify
	int oflag; // open flags -- same as open(2)
	int mode; // create mode flags -- same as open(2)
};
