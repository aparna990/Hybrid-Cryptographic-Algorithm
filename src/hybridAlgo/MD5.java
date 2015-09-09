package hybridAlgo;

public class MD5 {

	// S (Settled Constants) value declarations (Predefined)

		public static final int [][] Shift = { { 7, 12, 17, 22}, { 5,  9, 14, 20}, { 4, 11, 16, 23}, { 6, 10, 15, 21} };
		
	// A B C D Value Declarations	 (Little Endian Format : Least Significant in smallest address )

		public static final int ConstA = 0x67452301;
		public static final int ConstB = 0xEFCDAB89;
		public static final int ConstC = 0x98BADCFE;
		public static final int ConstD = 0x10325476;

	// T Value Declaration ( 2^32 * sin(i) )				//Static Block

		private static final int[] Tval = new int[64];
		 static			
		 {
		   for (int i=0; i < 64; i++)
			   Tval[i] =(int)(long)(Math.pow(2, 32) * Math.abs(Math.sin(i+1)));
		 }

	//Function Declarations

		//Compression Functions			

		public static int f(int x,int y,int z)
		{
			return ( (x&y) | (~x&z) );

		}

		public static int g(int x,int y,int z)
		{
			return ( (x&z) | (y&~z) );

		}

		public static int h(int x,int y,int z)
		{
			return (x^y^z);
		}

		public static int i(int x,int y,int z)
		{
			return y ^( x | ~z);
		}
		
		public static String toHexString(byte[] b)
		{
	/* The Hash function in bytes is received from func_md5 & converted to Hexadecimal representation */
		  StringBuilder sb = new StringBuilder();
			for(int i=0;i<b.length;i++)
					sb.append(String.format("%02X", b[i] & 0xFF));
			   return sb.toString();
		}

		public static String func_md5(byte[] message)
		{
			//Initializations
			int messageLenBytes = message.length;						// Message Length in BYTES
			long messageLenBits = (long) messageLenBytes<<3;			// Message Length in Bits (1 byte = 8 Bits)
			int numBlocks = ((messageLenBytes+8)>>>6)+1;   				// Message Length + (64 BITS ) Padding at the end with Message Length
			int totalLen = numBlocks << 6;								// Total Length in BYTES

			byte[] paddingZeroes = new byte[totalLen-messageLenBytes]; 	// in BYTES
			paddingZeroes[0]=(byte)0x80;								// First bit of FIRST BYTE of padding is 1 and rest followed by zeroes


			  for (int i = 0; i < 8; i++)
			  {  paddingZeroes[paddingZeroes.length - 8 + i] = (byte)messageLenBits;
			     messageLenBits >>>= 8;
			   }

			  int a = ConstA;
			  int b = ConstB;
			  int c = ConstC;
			  int d = ConstD;
			  int[] buffer = new int[16];	// 16*32bits = 512 -> 1 Block

			  // Go through every block of 64bytes (512 bits)

			  for(int i=0;i<numBlocks;i++)
			  {
				  int index=i*64;  
				  
			  // Filling Buffer with message + padding
				  for(int j=0;j<64;j++,index++)
				   buffer[j >>> 2] = ((int)((index < messageLenBytes) ? message[index] : paddingZeroes[index - messageLenBytes]) << 24) | (buffer[j >>> 2] >>> 8);
					 
				  int h0 = a;
				  int h1 = b;
				  int h2 = c;
				  int h3 = d;
				
			  // Compression Function 16*4 rounds
				  for(int j=0,k=0;j<64;j++,k++)
				  {		
					  int block = j/16;		// 0-15 ->1 | 16-31 ->2 | 32-47 ->3 | 48-63 ->4
					  int f=0;
					  int g = j;
					  switch(block)
					  {
					  	case 0:
					  		f = f(b,c,d);
					  		break;

					  	case 1:
					  		f = g(b,c,d);
					  		g = (1 + 5*j)%16;
					  		break;

					  	case 2:
					  		f = h(b,c,d);
					  		g = (5+3*j)%16;
					  		break;

					  	case 3:
					  		f = i(b,c,d);
					  		g = (7*j)%16;
					  		break;
					  }

					int temp = b + Integer.rotateLeft(a + f + buffer[g] + Tval[j], Shift[block][k%4]);
					
					// Rotate a,b,c,d values
					a=d;
					d=c;
					c=b;
					b=temp;
				  }

				// Initializing values for Next Block of 512 bits

				a = a + h0;
				b = b + h1;
				c = c + h2;
				d = d + h3;
			  }

			  // FINAL RESULT :
			  byte[] md5 = new byte[16];
			   int x= 0;
			   int n;
			   for (int i = 0; i < 4; i++)
			   {
			      if(i==0)
					   n=a;
				   else
					   if(i==1)
						   n=b;
					   else
						   if(i==2)
							   n=c;
						   else
							   	n=d;
			     
			     for (int j = 0; j < 4; j++)
			     {
			       md5[x++] = (byte)n;		// Creation of 16*8 = 128 bit output
			       n = (n >> 8);			// N -> Integer = 32 bits = 4 bytes
			     }
			   }
			   
			   
			   String outputMD5;
			   outputMD5=toHexString(md5);
			   			   
			   return outputMD5;
		}

		
		public static void main(String[] args)
		{
			System.out.println("8th Semester Project -> Hybrid Cryptography Algorithm : Part 1 \"MD5 Encryption\"!");	
			
			String msg[]={"qwerty","zxcv","pwd123","test123","Karthik Hariharan","a","abc","Preethish Shetty","abcdefghijklmnopqrstuvwxyz","0123456789","ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "$123#"};
		    System.out.println("\nFinal Result : ");
			for(String s:msg)
			  System.out.println("0x"+(func_md5(s.getBytes()))+" <= "+"\""+s+"\"");		//.getBytes - > takes the ASCII value of the message and passes into Bytes array

			return;
		}

}