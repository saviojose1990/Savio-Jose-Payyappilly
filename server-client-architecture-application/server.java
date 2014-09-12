/*
* File : server.java
*
* Description : This class responds to the client using UDP sockets.
*
* Author Name : Savio Jose Payyappilly
*
*/


package package_receiver;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Random;

public class receiver_group23 
{
	public static void main(String[] args) throws Exception
	{
		byte[] key=new byte[]{-31,82,1,53,86,-100,50,-30};

		InetAddress transmitter_add;// transmitter's IP address object
		Random randGen = new Random();		

		final int receiver_port = 9999;//receiver port number
		int transmitter_port;// to extract transmitter port number from the received packet
		int DATA_packet_num=0;//to indicate the number of the received DATA packet
		int check=0;//to check that 351 bytes of received data is decoded only once (when 9th. DATA packet is received for the first time) even if the ninth DATA packet is received more than one time
		int b=0;
		int j=0;
		
		boolean check_integritycheck;
		
		byte temp;
		
		byte[] initial_seq_num=new byte[2];
		byte[] expected_seq_num=new byte[2];
		byte[] generate_integritycheck=new byte[2];
		byte[] nonce=new byte[8];
		byte[] K=new byte[16];//interleaved initial K formed by interleaving key and nonce
		byte[] T=new byte[256];
		byte[] S=new byte[256];
		byte[] total_payload=new byte[351];// to store total 351 bytes of received data
		
		byte[] received_data=new byte[48];
		DatagramPacket received_packet=new DatagramPacket(received_data,received_data.length);
		
		byte[] dack_data=new byte[6];
		DatagramPacket DACK = new DatagramPacket(dack_data,dack_data.length);
		
		byte[] iack_data=new byte[14];
		DatagramPacket IACK = new DatagramPacket(iack_data,iack_data.length);
	
		// receiver socket, listening on port receiver_port
		DatagramSocket socket_rx = new DatagramSocket(receiver_port);

		randGen.nextBytes(nonce);//gives random value to 8 bytes of nonce
		
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
		
		//initialization of S adding values of interleaved K bytes to T
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
		
		// do this forever
		while(true)
		{
			// receiving transmitter's request
			socket_rx.receive(received_packet);
		
			//extracting trasmitter information out of the received UDP packet
			transmitter_add = received_packet.getAddress();
			transmitter_port = received_packet.getPort();
			
			//checks if all the bytes received in the received_packet is correct
			check_integritycheck=check_integritycheck(received_data);
			if(check_integritycheck)// checks if all bytes received in the INIT packet are correct (integrity check successful)
			{
				
				if(received_data[0]==0x00 && received_data[1]==0x00)//checks if received packet is INIT or DATA packet with the help of packet type field
				{
					System.out.println("Received packet is INIT");
			
					// initializing initial sequence number with the information received from INIT 
					initial_seq_num[0]=received_data[2];
					initial_seq_num[1]=received_data[3];
								
					iack_data[0]=0x00;// setting packet type 
					iack_data[1]=0x01;// setting packet type
					
					//setting other bytes in the IACK packet
					iack_data[2]=initial_seq_num[0];
					iack_data[3]=initial_seq_num[1];
					
					for(int i=0;i<=7;i++)
					{
						iack_data[i+4]=nonce[i];
					}
					
					//generating integrity check for IACK
					generate_integritycheck=generate_integritycheck(iack_data);
					iack_data[12]=generate_integritycheck[0];
					iack_data[13]=generate_integritycheck[1];

					// setting up the response UDP packet object
					IACK.setAddress(transmitter_add);
					IACK.setPort(transmitter_port);
					
					//sending IACK to transmitter
					socket_rx.send(IACK);
					
					System.out.println("Sent IACK to transmitter\n");
				}
				else if(received_data[0]==0x00 && (received_data[1]==0x02 || received_data[1]==0x03))//checks if received packet is INIT or DATA packet with the help of packet type field
				{
					System.out.println("Received packet is DATA packet");
					
					dack_data[0]=0x00;// setting packet type
					dack_data[1]=0x04;// setting packet type
					
					// if the DATA packet received is the first DATA packet then initialing the expected sequence number with initial sequence number
					if(DATA_packet_num==0)
					{
						expected_seq_num=initial_seq_num;
					}
					
					// if the sequence number in the received DATA packet and the expected sequence number by the receiver are same (DATA packet is received for the first time)
					if(expected_seq_num[0]==received_data[2] && expected_seq_num[1]==received_data[3])
					{
						b=DATA_packet_num*40;
						
						DATA_packet_num++;
						System.out.println("Packet number: "+DATA_packet_num);
						
						//updating the sequence number in the DACK packet
						dack_data[2]=received_data[2];
						dack_data[3]=received_data[3];
						
						//extracting the payload from the received DATA packet
						for(int i=6;i<=(received_data[5]+5);i++)
						{
							total_payload[b]=received_data[i];
							b++;
						}
						
						//incrementing the expected sequence number
						if(expected_seq_num[1]!=(byte)11111111)
						{
							expected_seq_num[1]++;
						}
						else if(expected_seq_num[1]==(byte)1111111)
						{
							expected_seq_num[1]=0;
							expected_seq_num[0]++;
						}
					}
					
					// if the sequence number in the received DATA packet is not matching the expected sequence number by the receiver (DATA packet is received for more than one time, it is duplicate DATA packet)
					else
					{
						System.out.println("It is duplicate packet number: "+DATA_packet_num);
						if(DATA_packet_num==9)
						{
							//to ensure that 351 bytes of received data is decrypted only once (when 9th. DATA packet is received for the first time)
							//if 9th. DATA packet is received for 2nd. , 3rd. or 4th. time (duplicate 9th. DATA packets are received) then decryption should not be done
							check=1; //check=1 when 9th. DATA packet is received for the second time
						}
					}
					
					//generating integrity check for DACK packet
					generate_integritycheck=generate_integritycheck(dack_data);
					dack_data[4]=generate_integritycheck[0];
					dack_data[5]=generate_integritycheck[1];
					
					// setting up the response UDP packet object
					DACK.setAddress(transmitter_add);
					DACK.setPort(transmitter_port);
					
					//sending DACK to receiver
					socket_rx.send(DACK);
					System.out.println("Sent DACK\n");
					
					//check=0 indicates that 9th. DATA packet is received for the first time (it is not duplicate DATA packet)
					if(DATA_packet_num==9 && check==0)
					{
						byte[] total_decrypted_payload=decryption(S,total_payload);
						System.out.println("\n               Data byte  -->  Decrypted data byte");
						for(int i=0;i<=350;i++)
						{
							System.out.println("Byte number "+i+")     "+total_payload[i]+"  -->  "+total_decrypted_payload[i]);
						}
					}
				}//end of if else loop for data packet
			}
			else
			{
				System.out.println("Received packet fails integrity check !!");
			}

		}//while ends
	}// main ends
	
	private static byte[] generate_integritycheck(byte[] packet_tx)// code for generating the integrity check
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
	
	private static byte[] decryption(byte S[], byte total_payload[])// code to decrypt actual 351 bytes of received data
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
