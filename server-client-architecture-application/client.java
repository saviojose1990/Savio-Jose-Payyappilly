/*
* File : client.java
*
* Description : This class initiates a connection and communicates with the server using UDP sockets.
*
* Author Name : Savio Jose Payyappilly
*
*/


package package_transmitter;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Random;

public class transmitter_group23 
{
	public static void main(String[] args) throws Exception
	{
		byte[] key=new byte[]{-31,82,1,53,86,-100,50,-30};
		
		DatagramSocket socket_tx = new DatagramSocket();//creating the UDP transmitter socket
		
		InetAddress receiver_add = InetAddress.getLocalHost();//loop back the request to the same machine
		Random randGen = new Random();		

		final int receiver_port = 9999;//receiver port number
		final int time_out = 1000;//initial timeout value in milliseconds
		int DATA_packet_num;
		
		boolean check_integritycheck;
		
		byte[] initial_seq_num=new byte[2]; //we need to generate a random initial sequence number
		byte[] generate_integritycheck=new byte[2];//we need to generate integrity check for each transmitted packet
		
		byte[] init_data=new byte[6];
		DatagramPacket INIT = new DatagramPacket(init_data, init_data.length,receiver_add, receiver_port);// creating the UDP packed to be sent
		
		byte[] iack_data = new byte[14];
		DatagramPacket IACK  = new DatagramPacket(iack_data,iack_data.length);// creating the receive UDP packet
		
		init_data[0]=0x00;//packet type
		init_data[1]=0x00;//packet type
		
		//generating a random initial sequence number
		randGen.nextBytes(initial_seq_num);
		
		init_data[2]=initial_seq_num[0];// seq number is given to init_pakcet
		init_data[3]=initial_seq_num[1];// seq number is given to init_packet
			
		//generating integrity check
		generate_integritycheck=generate_integritycheck(init_data);
		init_data[4]=generate_integritycheck[0];
		init_data[5]=generate_integritycheck[1];

		// packet INIT is ready to be sent
		for(int count=1;count<=4;count++)// loop for sending INIT packet again in case of timeout or incorrectly received IACK packet
		{
			socket_tx.send(INIT);// sending the UDP packet to the receiver
			System.out.println("\nSent INIT for "+count+" time");
			socket_tx.setSoTimeout(2^((count)-1)*time_out);// setting the timeout for the socket
			
			// receiving the receiver's response
			try
			{
				socket_tx.receive(IACK); // the timeout timer starts ticking here
				System.out.println("Received IACK after sending INIT for "+count+" time");
			}
			catch(InterruptedIOException e)
			{
				// timeout - timer expired before receiving IACK from the receiver
				System.out.println("Time out after sending INIT for "+count+" time");
				if(count==4)//declare communication failure if INIT is sent four times yet there is some error in receiving IACK packet
				{
					System.out.print("\nConnection could not be established");
					System.exit(0);
				}
				else
				{
					continue;//if nothing is received then skip the processes and directly go to the next iteration to send INIT again
				}
			}
			
			check_integritycheck=check_integritycheck(iack_data);
			if(check_integritycheck)// checks if all bytes received in the IACK packet are correct (integrity check successful)
			{
				if(iack_data[0]==0x00 && iack_data[1]==0x01)// IACK packet type check
				{
					if(iack_data[2]==initial_seq_num[0] && iack_data[3]==initial_seq_num[1])// checks initial sequence number echoed in the IACK packet
					{
						System.out.println("All checks successful for IACK");
						break;//if all checks of IACK are successful then we DO NOT want to send INIT again, so breaking the loop 
					}
					else
					{
						System.out.println("Initial sequence number echoed in the IACK packet is not matching to the initial sequence number sent in INIT packet");
						if(count==4)
						{
							System.out.print("\nConnection could not be established");
							System.exit(0);
						}
					}
				}//if loop of packet type check ends
				else
				{
					System.out.println("Packet type is not matching");
					if(count==4)
					{
						System.out.print("\nConnection could not be established");
						System.exit(0);
					}
				}
			}// if loop of integrity check ends
			else
			{
				System.out.println("Checksum is not matching");
				if(count==4)
				{
					System.out.print("\nConnection could not be established");
					System.exit(0);
				}
			}
		}// for loop of sending INIT again (in case some error has occurred) ends

		//if IACK is received correctly then start preparing DATA packets
		int j=0;
		int b=0;
		
		byte temp;
		
		byte[] seq_num_to_transmit=new byte[2];
		byte[] nonce=new byte[8];
		byte[] K=new byte[16];			
		byte[] T=new byte[256];
		byte[] S=new byte[256];	
		byte[] total_payload=new byte[351];
		byte[] total_encrypted_payload=new byte[351];//=encryption(S,total_payload);
		
		byte[] dack_data = new byte[6];
		DatagramPacket DACK  = new DatagramPacket(dack_data,dack_data.length);// creating the receive UDP packet
		
		byte[] data_data=new byte[48];
		DatagramPacket DATA = new DatagramPacket(data_data, data_data.length,receiver_add, receiver_port);// creating the UDP packed to be sent
		
		seq_num_to_transmit=initial_seq_num;// initializing seq_num_to_tranmsit with the initial seq number
		
		//extracting nonce from received IACK packet
		for(int i=0;i<=7;i++)
		{
			nonce[i]=iack_data[i+4];
		}
				
		//interleaving nonce and key to get the initial key K		
		for(int i=0;i<=15;i++)
		{
			if(i%2==0)
			{
				K[i]=key[i/2];
			}
			else
			{
				K[i]=nonce[i/2];
			}
		}	
		
		//initialization of S and adding values of interleaved K bytes to T
		for(int i=0; i<=255; i++)
		{
			S[i]=(byte)i;
			T[i]=K[i%16];
		}
		
		//initial permutation of S
		for(int i=0;i<=255;i++)
		{
			j=Math.abs((j+S[i]+T[i])%256);
			temp=S[i];
			S[i]=S[j];
			S[j]=temp;
		}
		
		randGen.nextBytes(total_payload);//gives random value to 351 bytes of actual data
		total_encrypted_payload=encryption(S,total_payload);//encrypts the randomly generated 351 bytes of data
			
		//Printing the actual data byte and the corresponding encrypted data byte
		System.out.println("\n               Data byte  -->  Encrypted data byte");
		for(int i=0;i<=350;i++)
		{
			System.out.println("Byte number "+i+")     "+total_payload[i]+"  -->  "+total_encrypted_payload[i]);
		}	
		
		data_data[0]=0x00;//first byte of DATA packet is always 00
		data_data[4]=0;//first byte of length representation is always 00
		
		for(DATA_packet_num=1;DATA_packet_num<=9;DATA_packet_num++)// for loop of DATA packets
		{
			data_data[2]=seq_num_to_transmit[0];
			data_data[3]=seq_num_to_transmit[1];
			
			b=(DATA_packet_num-1)*40;//used to stuff 40 bytes of payload field in the DATA packet from 351 bytes of encrypted data array 
			
			if(DATA_packet_num!=9)
			{
				data_data[1]=0x02;// indicates that DATA packet is NOT the last DATA packet
				data_data[5]=40;
				for(int a=6;a<=45;a++) //adding values from 351 bytes of encrypted total payload to 40 byte payload
				{
					data_data[a]=total_encrypted_payload[b];
					b++;
				}
			}
			else //DATA_packet_num==9
			{
				data_data[1]=0x03;// indicates that DATA packet is the last DATA packet
				data_data[5]=31;// indicates the number of data bytes sent in the payload, NOT counting the padding bytes
				for(int a=6;a<=36;a++) //adding values from encrypted total payload to 31 byte payload
				{
					data_data[a]=total_encrypted_payload[b];
					b++;
				}
				for(int a=37;a<=45;a++) //padding last 9 bytes in payload of last DATA packet with zero
				{
					data_data[a]=00;
				}
			}
			
			//generating integrity check
			generate_integritycheck=generate_integritycheck(data_data);
			data_data[46]=generate_integritycheck[0];
			data_data[47]=generate_integritycheck[1];
			
			//DATA packet is ready
			for(int count=1;count<=4;count++)//loop for sending DATA packet again in case of timeout or incorrectly received DACK packet
			{
				socket_tx.send(DATA);// sending the UDP packet to the receiver
				System.out.println("\nSent DATA "+DATA_packet_num+" for "+count+" time");
				socket_tx.setSoTimeout(2^((count)-1)*time_out);// setting the timeout for the socket
				
				// receiving the receiver's response
				try
				{
					socket_tx.receive(DACK); // the timeout timer starts ticking here
					System.out.println("Received DACK after sending DATA "+DATA_packet_num+" for "+count+" time");
				}
				catch(InterruptedIOException e)
				{
					// timeout - timer expired before receiving IACK from the receiver
					System.out.println("Time out after sending DATA "+DATA_packet_num+" for "+count+" time");
					if(count==4)//declare communication failure if DATA is sent four times yet there is some error in receiving DACK packet
					{
						System.out.print("\nConnection could not be established");
						System.exit(0);
					}
					else
					{
						continue;//if nothing is received then skip the processes and directly go to the next iteration to send DATA packet again
					}
				}
				
				check_integritycheck=check_integritycheck(dack_data);
				if(check_integritycheck)// checks if all bytes received in the DACK packet are correct (integrity check successful)
				{
					if(dack_data[0]==0x00 && dack_data[1]==0x04)// DACK packet type check
					{
						if(dack_data[2]==seq_num_to_transmit[0] && dack_data[3]==seq_num_to_transmit[1])// checks if the last packet correctly received by the receiver is same as the last packet transmitted by the transmitter
						{
							System.out.println("All checks successful for DACK");
							
							//incrementing the sequence number to be transmitted for the next DATA packet
							if(seq_num_to_transmit[1]!=(byte)11111111)
							{
								seq_num_to_transmit[1]++;
							}
							else if(seq_num_to_transmit[1]==(byte)1111111)
							{
								seq_num_to_transmit[1]=0;
								seq_num_to_transmit[0]++;
							}
							break;//if all checks of DACK are successful then we DO NOT want to send the same DATA packet again, so breaking the loop 
						}//if of sequence number check ends
						else
						{
							System.out.println("Sequence number in the DACK packet is not matching to the sequence number sent in DATA packet");
							if(count==4)
							{
								System.out.print("\nConnection could not be established");
								System.exit(0);
							}
						}
					}// if of packet type check ends
					else
					{
						System.out.println("Packet type is not matching");
						if(count==4)
						{
							System.out.print("\nConnection could not be established");
							System.exit(0);
						}
					}//if loop of integrity check ends
				}
				else
				{
					System.out.println("Integrity check is not successful");
					if(count==4)
					{
						System.out.print("\nConnection could not be established");
						System.exit(0);
					}
				}
			}//for loop of sending the same DATA packet again for 4 times(in case some error has occurred) ends
			
		}// for loop for sending DATA packet 1 to DATA packet 9 ends (all 351 bytes are transmitted)
	
		//closing the socket
		socket_tx.close();
		System.out.print("\nTransmitter socket is closed now");
	}// main ends
	
	static byte[] generate_integritycheck(byte[] packet_tx)// code for generating the integrity check
	{
		byte[] check=new byte[]{0,0};
		for (int i=0;i<=packet_tx.length-4;i=i+2)
		{
			check[0]=(byte) (check[0]^packet_tx[i]);
			check[1]=(byte) (check[1]^packet_tx[i+1]);
		}
		return check;
	}
	
	private static boolean check_integritycheck(byte[] packet_rx)// code for checking the integrity check
	{
		byte[] check=new byte[]{0,0};
		for(int i=0;i<=packet_rx.length-2;i=i+2)
		{
			check[0]=(byte) (check[0]^packet_rx[i]);
			check[1]=(byte) (check[1]^packet_rx[i+1]);
		}
		if(check[0]==0 && check[1]==0)
			return true;
		else
			return false;
	}
	
	private static byte[] encryption(byte S[], byte total_payload[])// code to encrypt actual 351 data bytes
	{
		byte[] total_encrypted_payload=new byte[351];
		int count=0,x=0,y=0,t=0;
		byte temp,k;
		while(count<=350)
		{
			x=(x+1)%256;
			y=Math.abs((y+S[x])%256);
			temp=S[y];
			S[y]=S[x];
			S[x]=temp;
			t=(Math.abs(S[x]+S[y])%256);
			k=S[t];
			total_encrypted_payload[count]=(byte) (total_payload[count]^k);
			count++;
		}
		return total_encrypted_payload;
	}
}// class ends
