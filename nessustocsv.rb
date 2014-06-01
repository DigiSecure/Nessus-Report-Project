#!/usr/bin/ruby

require 'nessus'
require 'fastercsv'
# Class nessusToCsv 
#  Class cveDb
#  Class recommendations
#
#  Get .nessus file from ARGF
# IF ARGF is a list of .nessus files iterate else no
#   Perform some logic: 
#   	Remove Informational 
#   	Remove Port Zero due to Noise
#      	If event has no bid/cve
#      			Output only H,M,L
#      		else if event has bid/cve
#      			output C,H,M,L 
#      			& Critical 
#      
#
#
#
#   Determine unsupported systems
#   	"Unsupported Installation Detection" - Windows
#   	"Unsupported * Operating System" -- Everything else
#
#
#
#

class NessusToCsv
	def initialize(file)
		@file = file
	end

	def informational()
	#Header Line
		nessus_info = []
		nessus_info <<  "IP,Severity,BID,CVE,Finding,Solution\n"
	# Get each host with onlu Informational items that is not critical 

        Nessus::Parse.new("#{@file}") do |scan|
	scan.each_host do |host|
	       next if host.event_count.zero?    # Next Host If Event Count Is Zero.
		host.each_event do |event|
	       		next if !event.bid.empty? 
	       		next if !event.cve.empty?
		        next if event.critical?	
	       		nessus_info << host.ip + "," + event.severity.in_words + "," + event.bid.join(" ") + "," + event.cve.join(" ") + "," + event.name + "," + event.solution.to_s.gsub(",","").gsub("\n","") + "\n"
    	    end
	  end
       	end
		File.open("#{@file}.info.csv","w+") do |csv|
			nessus_info.each {|row| csv.print(row)}
		end

	end

	def critical()
		nessus_info = []
		nessus_info <<  "IP,Severity,BID,CVE,Finding,Solution\n"
        Nessus::Parse.new("#{@file}") do |scan|
	scan.each_host do |host|
	       next if host.event_count.zero?    # Next Host If Event Count Is Zero.
		host.each_event do |event|
	       		next if host.event_count.zero?    # Next Host If Event Count Is Zero.
		        next if !event.critical?
			next if event.cve.empty? || event.bid.empty?
	       		nessus_info << host.ip + "," + event.severity.in_words + "," + event.bid.join(" ") + "," + event.cve.join(" ") + "," + event.name + "," + event.solution.to_s.gsub(",","").gsub("\n","") + "\n"
    	    	end
	end
	  end
		File.open("#{@file}.crit.csv","w+") do |csv|
			nessus_info.each {|row| csv.print(row)}
		end


	end

	def default() 
		nessus_info = []
		nessus_info <<  "IP,Severity,BID,CVE,Finding, Solution"
        Nessus::Parse.new("#{@file}") do |scan|
	scan.each_host do |host|
	       next if host.event_count.zero?    # Next Host If Event Count Is Zero.
		host.each_event do |event|
	       		next if host.event_count.zero?    # Next Host If Event Count Is Zero.
		        next if event.informational?
		        next if event.critical?
			next if event.cve.empty? || event.bid.empty?
	       		nessus_info << host.ip + "," + event.severity.in_words + "," + event.bid.join(" ") + "," + event.cve.join(" ") + "," + event.name + "," + event.solution.to_s.gsub(",","").gsub("\n","") + "\n"
    	    	end
	      end	
	    end
		File.open("#{@file}.HML.csv","w+") do |csv|
			nessus_info.each {|row| csv.print(row)}
		end
	
      	end
	
end





ARGF.argv.each do |argument|
	if File.file?("#{argument}")
          nessus = NessusToCsv.new("#{argument}")
	   nessus.critical
	   nessus.default
	   nessus.informational
	else
	 Print "Error no file input"
	end
end
